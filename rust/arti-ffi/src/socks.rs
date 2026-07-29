//! A SOCKS5 front-end onto `TorClient::connect`.
//!
//! bine reaches Tor through `golang.org/x/net/proxy`, so this only needs the
//! subset of RFC 1928 that client speaks: CONNECT, with either no
//! authentication or username/password (which C tor overloads to mean stream
//! isolation, via `IsolateSOCKSAuth`).

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use arti_client::{IsolationToken, StreamPrefs, TorClient};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tor_rtcompat::PreferredRuntime;

/// SOCKS protocol version 5.
const VER5: u8 = 0x05;
/// Authentication method: none required.
const AUTH_NONE: u8 = 0x00;
/// Authentication method: username/password (RFC 1929).
const AUTH_USERPASS: u8 = 0x02;
/// Sentinel meaning "none of the offered methods are acceptable".
const AUTH_NONE_ACCEPTABLE: u8 = 0xFF;
/// The only command we implement.
const CMD_CONNECT: u8 = 0x01;
/// Address type: IPv4.
const ATYP_IPV4: u8 = 0x01;
/// Address type: domain name.
const ATYP_DOMAIN: u8 = 0x03;
/// Address type: IPv6.
const ATYP_IPV6: u8 = 0x04;

/// Reply codes we hand back to the client.
mod rep {
    /// Success.
    pub const OK: u8 = 0x00;
    /// Generic failure.
    pub const GENERAL_FAILURE: u8 = 0x01;
    /// Unsupported CMD.
    pub const CMD_NOT_SUPPORTED: u8 = 0x07;
    /// Unsupported ATYP.
    pub const ATYP_NOT_SUPPORTED: u8 = 0x08;
}

/// SOCKS username and password, as supplied by the client.
type Credentials = (Vec<u8>, Vec<u8>);

/// Maps SOCKS credentials onto isolation tokens, so that two clients using
/// different credentials never share a circuit.
#[derive(Default)]
struct Isolation(Mutex<HashMap<Credentials, IsolationToken>>);

impl Isolation {
    /// Return the token for these credentials, minting one on first use.
    fn token_for(&self, user: Vec<u8>, pass: Vec<u8>) -> IsolationToken {
        let mut map = self.0.lock().expect("poisoned lock");
        *map.entry((user, pass)).or_insert_with(IsolationToken::new)
    }
}

/// Bind a SOCKS listener and serve it until the returned task is dropped.
///
/// Returns the address actually bound, which is what `GETINFO
/// net/listeners/socks` reports back to bine.
pub async fn spawn(
    client: Arc<TorClient<PreferredRuntime>>,
    bind: SocketAddr,
) -> io::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let listener = TcpListener::bind(bind).await?;
    let addr = listener.local_addr()?;
    let handle = tokio::spawn(async move {
        let isolation = Arc::new(Isolation::default());
        loop {
            let (sock, _peer) = match listener.accept().await {
                Ok(v) => v,
                // A transient accept error should not take the proxy down.
                Err(_) => continue,
            };
            let client = Arc::clone(&client);
            let isolation = isolation.clone();
            tokio::spawn(async move {
                let _ = serve_one(client, isolation, sock).await;
            });
        }
    });
    Ok((addr, handle))
}

/// Run the SOCKS5 exchange for a single accepted connection.
async fn serve_one(
    client: Arc<TorClient<PreferredRuntime>>,
    isolation: Arc<Isolation>,
    mut sock: TcpStream,
) -> io::Result<()> {
    let creds = negotiate_auth(&mut sock).await?;
    let (host, port) = match read_connect_request(&mut sock).await? {
        Some(target) => target,
        // The request was answered with an error reply already.
        None => return Ok(()),
    };

    let mut prefs = StreamPrefs::new();
    if let Some((user, pass)) = creds {
        prefs.set_isolation(isolation.token_for(user, pass));
    }

    let stream = match client
        .connect_with_prefs((host.as_str(), port), &prefs)
        .await
    {
        Ok(s) => s,
        Err(_) => {
            reply(&mut sock, rep::GENERAL_FAILURE).await?;
            return Ok(());
        }
    };
    reply(&mut sock, rep::OK).await?;

    let mut stream = stream.compat();
    let _ = tokio::io::copy_bidirectional(&mut sock, &mut stream).await;
    Ok(())
}

/// Read a CONNECT request, returning the target it names.
///
/// Returns `Ok(None)` when the request was rejected and an error reply already
/// written, which the caller should treat as a completed exchange.
async fn read_connect_request<S>(sock: &mut S) -> io::Result<Option<(String, u16)>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Request: VER CMD RSV ATYP ...
    let mut head = [0u8; 4];
    sock.read_exact(&mut head).await?;
    if head[0] != VER5 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bad SOCKS version",
        ));
    }
    if head[1] != CMD_CONNECT {
        reply(sock, rep::CMD_NOT_SUPPORTED).await?;
        return Ok(None);
    }

    let host = match head[3] {
        ATYP_IPV4 => {
            let mut b = [0u8; 4];
            sock.read_exact(&mut b).await?;
            std::net::Ipv4Addr::from(b).to_string()
        }
        ATYP_IPV6 => {
            let mut b = [0u8; 16];
            sock.read_exact(&mut b).await?;
            std::net::Ipv6Addr::from(b).to_string()
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            sock.read_exact(&mut len).await?;
            let mut b = vec![0u8; len[0] as usize];
            sock.read_exact(&mut b).await?;
            String::from_utf8(b)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad domain"))?
        }
        _ => {
            reply(sock, rep::ATYP_NOT_SUPPORTED).await?;
            return Ok(None);
        }
    };
    let mut port = [0u8; 2];
    sock.read_exact(&mut port).await?;
    Ok(Some((host, u16::from_be_bytes(port))))
}

/// Perform the SOCKS5 method negotiation, returning credentials if the client
/// authenticated with username/password.
async fn negotiate_auth<S>(sock: &mut S) -> io::Result<Option<Credentials>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut hello = [0u8; 2];
    sock.read_exact(&mut hello).await?;
    if hello[0] != VER5 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bad SOCKS version",
        ));
    }
    let mut methods = vec![0u8; hello[1] as usize];
    sock.read_exact(&mut methods).await?;

    // Prefer no-auth; fall back to username/password, which Tor clients use to
    // request stream isolation rather than to prove anything.
    if methods.contains(&AUTH_NONE) {
        sock.write_all(&[VER5, AUTH_NONE]).await?;
        return Ok(None);
    }
    if !methods.contains(&AUTH_USERPASS) {
        sock.write_all(&[VER5, AUTH_NONE_ACCEPTABLE]).await?;
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "no acceptable SOCKS auth method",
        ));
    }

    sock.write_all(&[VER5, AUTH_USERPASS]).await?;
    // RFC 1929: VER ULEN UNAME PLEN PASSWD
    let mut ver = [0u8; 1];
    sock.read_exact(&mut ver).await?;
    let mut ulen = [0u8; 1];
    sock.read_exact(&mut ulen).await?;
    let mut user = vec![0u8; ulen[0] as usize];
    sock.read_exact(&mut user).await?;
    let mut plen = [0u8; 1];
    sock.read_exact(&mut plen).await?;
    let mut pass = vec![0u8; plen[0] as usize];
    sock.read_exact(&mut pass).await?;
    // Any credentials are accepted; they only select an isolation token.
    sock.write_all(&[0x01, 0x00]).await?;
    Ok(Some((user, pass)))
}

/// Send a SOCKS5 reply with an all-zero bound address, which clients ignore
/// for CONNECT.
async fn reply<S>(sock: &mut S, code: u8) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    sock.write_all(&[VER5, code, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
        .await
}

#[cfg(test)]
mod test {
    use super::*;

    /// Drive a helper against an in-memory duplex, returning what it produced
    /// alongside everything written back to the client.
    async fn exchange<T, F, Fut>(request: &[u8], f: F) -> (io::Result<T>, Vec<u8>)
    where
        F: FnOnce(tokio::io::DuplexStream) -> Fut,
        Fut: std::future::Future<Output = (io::Result<T>, tokio::io::DuplexStream)>,
    {
        let (mut client, server) = tokio::io::duplex(1024);
        client.write_all(request).await.unwrap();

        let (result, mut server) = f(server).await;
        server.shutdown().await.ok();

        let mut written = Vec::new();
        client.read_to_end(&mut written).await.ok();
        (result, written)
    }

    async fn negotiate(request: &[u8]) -> (io::Result<Option<Credentials>>, Vec<u8>) {
        exchange(request, |mut s| async move {
            let r = negotiate_auth(&mut s).await;
            (r, s)
        })
        .await
    }

    async fn connect_request(request: &[u8]) -> (io::Result<Option<(String, u16)>>, Vec<u8>) {
        exchange(request, |mut s| async move {
            let r = read_connect_request(&mut s).await;
            (r, s)
        })
        .await
    }

    #[tokio::test]
    async fn no_auth_is_preferred() {
        // VER=5, 2 methods: none and username/password.
        let (creds, written) = negotiate(&[VER5, 2, AUTH_NONE, AUTH_USERPASS]).await;
        assert!(creds.unwrap().is_none());
        assert_eq!(written, vec![VER5, AUTH_NONE]);
    }

    #[tokio::test]
    async fn username_password_yields_credentials() {
        let mut req = vec![VER5, 1, AUTH_USERPASS];
        // RFC 1929: VER ULEN UNAME PLEN PASSWD
        req.extend_from_slice(&[0x01, 2, b'h', b'i', 3, b'a', b'b', b'c']);

        let (creds, written) = negotiate(&req).await;
        let (user, pass) = creds.unwrap().expect("credentials");
        assert_eq!(user, b"hi");
        assert_eq!(pass, b"abc");
        // Method selection, then a success reply to the auth sub-negotiation.
        assert_eq!(written, vec![VER5, AUTH_USERPASS, 0x01, 0x00]);
    }

    #[tokio::test]
    async fn unacceptable_auth_is_refused() {
        // GSSAPI only, which we do not implement.
        let (creds, written) = negotiate(&[VER5, 1, 0x01]).await;
        assert!(creds.is_err());
        assert_eq!(written, vec![VER5, AUTH_NONE_ACCEPTABLE]);
    }

    #[tokio::test]
    async fn rejects_a_non_socks5_greeting() {
        let (creds, _) = negotiate(&[0x04, 1, AUTH_NONE]).await;
        assert!(creds.is_err());
    }

    #[tokio::test]
    async fn reads_a_domain_target() {
        // This is the form bine's dialer uses for .onion addresses.
        let mut req = vec![VER5, CMD_CONNECT, 0x00, ATYP_DOMAIN, 11];
        req.extend_from_slice(b"example.com");
        req.extend_from_slice(&443u16.to_be_bytes());

        let (target, _) = connect_request(&req).await;
        assert_eq!(target.unwrap(), Some(("example.com".to_string(), 443)));
    }

    #[tokio::test]
    async fn reads_ipv4_and_ipv6_targets() {
        let mut v4 = vec![VER5, CMD_CONNECT, 0x00, ATYP_IPV4, 127, 0, 0, 1];
        v4.extend_from_slice(&8080u16.to_be_bytes());
        let (target, _) = connect_request(&v4).await;
        assert_eq!(target.unwrap(), Some(("127.0.0.1".to_string(), 8080)));

        let mut v6 = vec![VER5, CMD_CONNECT, 0x00, ATYP_IPV6];
        v6.extend_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
        v6.extend_from_slice(&80u16.to_be_bytes());
        let (target, _) = connect_request(&v6).await;
        assert_eq!(target.unwrap(), Some(("::1".to_string(), 80)));
    }

    #[tokio::test]
    async fn rejects_unsupported_commands() {
        // BIND, which we do not implement.
        let req = vec![VER5, 0x02, 0x00, ATYP_IPV4, 127, 0, 0, 1, 0, 80];
        let (target, written) = connect_request(&req).await;
        assert_eq!(target.unwrap(), None, "caller should stop, not connect");
        assert_eq!(written[1], rep::CMD_NOT_SUPPORTED);
    }

    #[tokio::test]
    async fn rejects_unsupported_address_types() {
        let req = vec![VER5, CMD_CONNECT, 0x00, 0x09];
        let (target, written) = connect_request(&req).await;
        assert_eq!(target.unwrap(), None);
        assert_eq!(written[1], rep::ATYP_NOT_SUPPORTED);
    }
}
