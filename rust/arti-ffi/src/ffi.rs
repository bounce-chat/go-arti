//! The C ABI consumed by the cgo bindings in `libtor`.
//!
//! Conventions, uniform across the surface:
//!
//!   * Handles are opaque `*mut Client`; every one must be released with
//!     [`arti_client_free`].
//!   * Structured values cross as JSON `char*`; the caller frees them with
//!     [`arti_string_free`]. A NULL return means "nothing" (not an error)
//!     unless the function also has an `err_out`.
//!   * Fallible calls take `err_out`; on failure they return NULL/-1 and store
//!     an owned message there, which the caller frees with
//!     [`arti_string_free`].
//!   * Panics are trapped at the boundary and converted to errors: an embedded
//!     library has no business aborting its host process.

use std::ffi::{c_char, c_int, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::Duration;

use crate::client::Client;
use crate::onion::AddRequest;

/// Allocate a C string, returning NULL if it cannot be represented.
fn to_c_string(s: &str) -> *mut c_char {
    match CString::new(s) {
        Ok(v) => v.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Store an owned error message in `err_out`, if the caller supplied one.
///
/// # Safety
/// `err_out` must be null or point to a writable `*mut c_char`.
unsafe fn set_err(err_out: *mut *mut c_char, msg: &str) {
    if !err_out.is_null() {
        *err_out = to_c_string(msg);
    }
}

/// Borrow a handle, or return `$default` if it is NULL.
macro_rules! client_or {
    ($ptr:expr, $default:expr) => {
        match unsafe { ($ptr as *const Client).as_ref() } {
            Some(c) => c,
            None => return $default,
        }
    };
}

/// Run `body`, converting a panic into an error message.
fn guard<T>(err_out: *mut *mut c_char, fallback: T, body: impl FnOnce() -> T) -> T {
    match catch_unwind(AssertUnwindSafe(body)) {
        Ok(v) => v,
        Err(_) => {
            unsafe { set_err(err_out, "internal error: arti panicked") };
            fallback
        }
    }
}

/// Read a required C string argument.
///
/// # Safety
/// `ptr` must be null or a NUL-terminated C string.
unsafe fn required_str<'a>(ptr: *const c_char, what: &str) -> Result<&'a str, String> {
    if ptr.is_null() {
        return Err(format!("{what} must not be null"));
    }
    CStr::from_ptr(ptr)
        .to_str()
        .map_err(|_| format!("{what} must be valid UTF-8"))
}

/// Return the version of Arti backing this library.
#[no_mangle]
pub extern "C" fn arti_version() -> *const c_char {
    // Static and NUL-terminated, so the caller never frees it.
    crate::ARTI_VERSION_C.as_ptr() as *const c_char
}

/// Create a client from a JSON configuration blob.
///
/// Returns NULL on failure, with a message in `err_out`.
///
/// # Safety
/// `config_json` must be a NUL-terminated C string; `err_out` must be null or
/// point to a writable `*mut c_char`.
#[no_mangle]
pub unsafe extern "C" fn arti_client_new(
    config_json: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut Client {
    guard(err_out, std::ptr::null_mut(), || {
        let json = match required_str(config_json, "config") {
            Ok(v) => v,
            Err(e) => {
                set_err(err_out, &e);
                return std::ptr::null_mut();
            }
        };
        match Client::new(json) {
            Ok(c) => Box::into_raw(Box::new(c)),
            Err(e) => {
                set_err(err_out, &e);
                std::ptr::null_mut()
            }
        }
    })
}

/// Start the client's listeners and background tasks. Does not block.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `client` must come from [`arti_client_new`] and not yet be freed.
#[no_mangle]
pub unsafe extern "C" fn arti_client_start(
    client: *mut Client,
    err_out: *mut *mut c_char,
) -> c_int {
    guard(err_out, -1, || {
        let client = client_or!(client, {
            set_err(err_out, "client must not be null");
            -1
        });
        match client.start() {
            Ok(()) => 0,
            Err(e) => {
                set_err(err_out, &e);
                -1
            }
        }
    })
}

/// Block until the client is shut down.
///
/// # Safety
/// `client` must come from [`arti_client_new`] and not yet be freed.
#[no_mangle]
pub unsafe extern "C" fn arti_client_wait(client: *mut Client) -> c_int {
    guard(std::ptr::null_mut(), -1, || {
        let client = client_or!(client, -1);
        client.wait();
        0
    })
}

/// Ask the client to stop, unblocking [`arti_client_wait`].
///
/// # Safety
/// `client` must come from [`arti_client_new`] and not yet be freed.
#[no_mangle]
pub unsafe extern "C" fn arti_client_shutdown(client: *mut Client) {
    guard(std::ptr::null_mut(), (), || {
        if let Some(client) = unsafe { (client as *const Client).as_ref() } {
            client.shutdown();
        }
    })
}

/// Release a client handle.
///
/// # Safety
/// `client` must come from [`arti_client_new`] and must not be used again.
#[no_mangle]
pub unsafe extern "C" fn arti_client_free(client: *mut Client) {
    if client.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let client = Box::from_raw(client);
        client.shutdown();
        drop(client);
    }));
}

/// Return the current bootstrap phase as JSON, or NULL.
///
/// # Safety
/// `client` must come from [`arti_client_new`] and not yet be freed.
#[no_mangle]
pub unsafe extern "C" fn arti_bootstrap_status(client: *mut Client) -> *mut c_char {
    guard(std::ptr::null_mut(), std::ptr::null_mut(), || {
        let client = client_or!(client, std::ptr::null_mut());
        match serde_json::to_string(&client.bootstrap_status()) {
            Ok(s) => to_c_string(&s),
            Err(_) => std::ptr::null_mut(),
        }
    })
}

/// Enable (non-zero) or disable (zero) use of the Tor network.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `client` must come from [`arti_client_new`] and not yet be freed.
#[no_mangle]
pub unsafe extern "C" fn arti_set_network_enabled(
    client: *mut Client,
    enabled: c_int,
    err_out: *mut *mut c_char,
) -> c_int {
    guard(err_out, -1, || {
        let client = client_or!(client, {
            set_err(err_out, "client must not be null");
            -1
        });
        match client.set_network_enabled(enabled != 0) {
            Ok(()) => 0,
            Err(e) => {
                set_err(err_out, &e);
                -1
            }
        }
    })
}

/// Return 1 if the network is enabled, 0 if not, -1 on a null handle.
///
/// # Safety
/// `client` must come from [`arti_client_new`] and not yet be freed.
#[no_mangle]
pub unsafe extern "C" fn arti_network_enabled(client: *mut Client) -> c_int {
    guard(std::ptr::null_mut(), -1, || {
        let client = client_or!(client, -1);
        c_int::from(client.network_enabled())
    })
}

/// Return the SOCKS listener address as `host:port`, or NULL if none is running.
///
/// # Safety
/// `client` must come from [`arti_client_new`] and not yet be freed.
#[no_mangle]
pub unsafe extern "C" fn arti_socks_addr(client: *mut Client) -> *mut c_char {
    guard(std::ptr::null_mut(), std::ptr::null_mut(), || {
        let client = client_or!(client, std::ptr::null_mut());
        match client.socks_addr() {
            Some(addr) => to_c_string(&addr.to_string()),
            None => std::ptr::null_mut(),
        }
    })
}

/// Launch an onion service from a JSON ADD_ONION request.
///
/// Returns a JSON response, or NULL with a message in `err_out`.
///
/// # Safety
/// `client` must come from [`arti_client_new`]; `req_json` must be a
/// NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn arti_onion_add(
    client: *mut Client,
    req_json: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    guard(err_out, std::ptr::null_mut(), || {
        let client = client_or!(client, {
            set_err(err_out, "client must not be null");
            std::ptr::null_mut()
        });
        let json = match required_str(req_json, "request") {
            Ok(v) => v,
            Err(e) => {
                set_err(err_out, &e);
                return std::ptr::null_mut();
            }
        };
        let req: AddRequest = match serde_json::from_str(json) {
            Ok(v) => v,
            Err(e) => {
                set_err(err_out, &format!("invalid request: {e}"));
                return std::ptr::null_mut();
            }
        };
        match client.onion_add(&req).and_then(|resp| {
            serde_json::to_string(&resp).map_err(|e| format!("cannot encode response: {e}"))
        }) {
            Ok(s) => to_c_string(&s),
            Err(e) => {
                set_err(err_out, &e);
                std::ptr::null_mut()
            }
        }
    })
}

/// Tear down a previously launched onion service.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `client` must come from [`arti_client_new`]; `service_id` must be a
/// NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn arti_onion_del(
    client: *mut Client,
    service_id: *const c_char,
    err_out: *mut *mut c_char,
) -> c_int {
    guard(err_out, -1, || {
        let client = client_or!(client, {
            set_err(err_out, "client must not be null");
            -1
        });
        let id = match required_str(service_id, "service id") {
            Ok(v) => v,
            Err(e) => {
                set_err(err_out, &e);
                return -1;
            }
        };
        match client.onion_del(id) {
            Ok(()) => 0,
            Err(e) => {
                set_err(err_out, &e);
                -1
            }
        }
    })
}

/// Wait up to `timeout_ms` for the next asynchronous event.
///
/// Returns the event as JSON, or NULL if none arrived in time.
///
/// # Safety
/// `client` must come from [`arti_client_new`] and not yet be freed.
#[no_mangle]
pub unsafe extern "C" fn arti_next_event(client: *mut Client, timeout_ms: c_int) -> *mut c_char {
    guard(std::ptr::null_mut(), std::ptr::null_mut(), || {
        let client = client_or!(client, std::ptr::null_mut());
        let timeout = Duration::from_millis(timeout_ms.max(0) as u64);
        match client.next_event(timeout) {
            Some(ev) => match serde_json::to_string(&ev) {
                Ok(s) => to_c_string(&s),
                Err(_) => std::ptr::null_mut(),
            },
            None => std::ptr::null_mut(),
        }
    })
}

/// Start collecting Arti's log records, at the given `EnvFilter` directives.
///
/// Returns 0 if the subscriber was installed, -1 if one was already present -
/// including one belonging to the host application, which is left alone.
/// Records are then drained with [`arti_next_log`].
///
/// This is process-wide: `tracing` permits only one subscriber.
///
/// # Safety
/// `directives` must be a NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn arti_log_enable(directives: *const c_char) -> c_int {
    guard(std::ptr::null_mut(), -1, || {
        let directives = match required_str(directives, "log directives") {
            Ok(v) => v,
            Err(_) => return -1,
        };
        // Mirroring to stderr stays tied to LIBTOR_LOG; a caller asking for
        // records wants them delivered, not printed behind its back.
        if crate::logs::install(directives, false) {
            0
        } else {
            -1
        }
    })
}

/// Wait up to `timeout_ms` for the next log record, as JSON:
///
///   {"level":"INFO","target":"tor_dirmgr","message":"..."}
///
/// Returns NULL if none arrived in time.
#[no_mangle]
pub extern "C" fn arti_next_log(timeout_ms: c_int) -> *mut c_char {
    guard(std::ptr::null_mut(), std::ptr::null_mut(), || {
        let timeout = Duration::from_millis(timeout_ms.max(0) as u64);
        match crate::logs::next(timeout) {
            Some(record) => match serde_json::to_string(&record) {
                Ok(s) => to_c_string(&s),
                Err(_) => std::ptr::null_mut(),
            },
            None => std::ptr::null_mut(),
        }
    })
}

/// Derive the 32-byte public key from a 64-byte expanded secret key.
///
/// Writes into `out`, which must have room for 32 bytes. Returns 0 on success,
/// -1 on failure.
///
/// # Safety
/// `secret` must point to `secret_len` readable bytes, and `out` to 32
/// writable bytes.
#[no_mangle]
pub unsafe extern "C" fn arti_public_key(
    secret: *const u8,
    secret_len: usize,
    out: *mut u8,
) -> c_int {
    guard(std::ptr::null_mut(), -1, || {
        if secret.is_null() || out.is_null() {
            return -1;
        }
        let secret = unsafe { std::slice::from_raw_parts(secret, secret_len) };
        match crate::onion::public_key_of(secret) {
            Some(public) => {
                unsafe { std::ptr::copy_nonoverlapping(public.as_ptr(), out, public.len()) };
                0
            }
            None => -1,
        }
    })
}

/// Sign a message with a 64-byte expanded ed25519 secret key.
///
/// Writes the 64-byte signature into `out`. Returns 0 on success, -1 on
/// failure.
///
/// # Safety
/// `secret` and `message` must point to the given number of readable bytes,
/// and `out` to 64 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn arti_sign(
    secret: *const u8,
    secret_len: usize,
    message: *const u8,
    message_len: usize,
    out: *mut u8,
) -> c_int {
    guard(std::ptr::null_mut(), -1, || {
        if secret.is_null() || out.is_null() {
            return -1;
        }
        let secret = unsafe { std::slice::from_raw_parts(secret, secret_len) };
        // A zero-length message is legitimate, but from_raw_parts still needs a
        // non-null, aligned pointer.
        let message = if message_len == 0 {
            &[][..]
        } else if message.is_null() {
            return -1;
        } else {
            unsafe { std::slice::from_raw_parts(message, message_len) }
        };
        match crate::onion::sign_with_expanded(secret, message) {
            Some(sig) => {
                unsafe { std::ptr::copy_nonoverlapping(sig.as_ptr(), out, sig.len()) };
                0
            }
            None => -1,
        }
    })
}

/// Free a string returned by this library.
///
/// # Safety
/// `s` must be null, or a pointer previously returned by one of the functions
/// in this module (but not [`arti_version`], whose result is static).
#[no_mangle]
pub unsafe extern "C" fn arti_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn version_is_nul_terminated_and_named() {
        let v = unsafe { CStr::from_ptr(arti_version()) }.to_str().unwrap();
        assert!(v.starts_with("Arti "), "got {v:?}");
    }

    #[test]
    fn null_handles_are_rejected_not_dereferenced() {
        let mut err: *mut c_char = std::ptr::null_mut();
        unsafe {
            assert_eq!(arti_client_start(std::ptr::null_mut(), &mut err), -1);
            assert!(!err.is_null());
            arti_string_free(err);

            assert!(arti_bootstrap_status(std::ptr::null_mut()).is_null());
            assert!(arti_socks_addr(std::ptr::null_mut()).is_null());
            assert_eq!(arti_network_enabled(std::ptr::null_mut()), -1);
            assert_eq!(arti_client_wait(std::ptr::null_mut()), -1);
            // Must be a no-op rather than a crash.
            arti_client_free(std::ptr::null_mut());
            arti_string_free(std::ptr::null_mut());
        }
    }

    #[test]
    fn bad_config_reports_an_error() {
        let mut err: *mut c_char = std::ptr::null_mut();
        let cfg = CString::new("{}").unwrap();
        let handle = unsafe { arti_client_new(cfg.as_ptr(), &mut err) };
        assert!(handle.is_null());
        assert!(!err.is_null());
        let msg = unsafe { CStr::from_ptr(err) }.to_str().unwrap().to_string();
        assert!(msg.contains("data_directory"), "got {msg:?}");
        unsafe { arti_string_free(err) };
    }
}
