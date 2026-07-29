package arti

// Compatibility with the key format existing installations already have on
// disk.
//
// The vectors below were produced by bine (github.com/alexballas/bine), which
// is what wrote those files. If any of this drifts, an installation silently
// loses its .onion address, which is not recoverable — so the expected values
// are frozen here rather than recomputed, and the dependency that produced
// them is gone.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// vector is one key and everything that must still be derivable from it.
type vector struct {
	// privateKey is the base64 of the 64-byte expanded secret, as stored.
	privateKey string
	// publicKey is the hex of the 32-byte public half.
	publicKey string
	// onionID is the service address, without the ".onion" suffix.
	onionID string
	// signatures maps a message to its hex-encoded signature.
	signatures map[string]string
}

// decode unpacks a vector's key material.
func (v vector) decode(t *testing.T) (priv []byte, pub ed25519.PublicKey) {
	t.Helper()

	priv, err := base64.StdEncoding.DecodeString(v.privateKey)
	if err != nil {
		t.Fatalf("decode private key: %v", err)
	}
	raw, err := hex.DecodeString(v.publicKey)
	if err != nil {
		t.Fatalf("decode public key: %v", err)
	}
	return priv, ed25519.PublicKey(raw)
}

// compatibilityVectors returns the frozen reference values.
func compatibilityVectors() []vector {
	vectors := []vector{
		{
			privateKey: "GAkIfWYsBNOZTogGWNngwhu+ugjJAXkVC74zrEB2EG4EXaVpqVHmEIYqaODh3mklM9mRumI9qQV5bVCkdMA2xA==",
			publicKey:  "1c4a135932068cab1c5bc183122ffbda1f3367008975f6ae35e1ae91bf00b87f",
			onionID:    "drfbgwjsa2gkwhc3ygbrel733iptgzyarf27nlrv4gxjdpyaxb75yfid",
			signatures: map[string]string{
				"":  "ed67eb1c1017fa0202ea16732e98a54e4b05c90cef6a310632e2a80dae4e5a80fc9fbdde13ee116977df05f4e3c6e913f114097eb38d1d831b43ea21e78c3306",
				"x": "90e03a97b6c7b62cf0a91adb9e7193407e860a3c26d867f3ab8b23e654dc828b948e9ed6a3a7e35855c9c598b07c93d720a7452fd671da36612555047c5f3407",
				"a handshake challenge of the usual length, 32b": "83591a45c28d2fa518928690699ff1d328d2afc3b96f15e03054e6542eab1a97903ecbc91cfe1cf30d4e9a9424073ee9f281a495f5a1f295d065197f0f105f06",
				"\x00\x01\x02 binary \xff\xfe":                   "4d2c5ade450af737f2099569d602c37ea1e1f1c585464330838bf58338828701552e855b97479562ace777fdb472f945743d9af2f1496c3b9304c3dd41c1a00f",
			},
		},
		{
			privateKey: "oPRwe3NfVEJL4Aw+jlldclFiKrhlS/Vg5cLHZywclEASIw0o8OBPfL+NwpcVPPZquhlX2/HAeW8o3tUzrVVrsQ==",
			publicKey:  "373f0d806a7249b7c1a873f79315fb7428f8497ba54d0647b39a25b04115f400",
			onionID:    "g47q3adkoje3pqniop3zgfp3oqupqsl3uvgqmr5ttis3aqiv6qadowid",
			signatures: map[string]string{
				"":  "e84c91f03f3f7f79317c9980e4d8432b612cc78e30f48c0e0745658d5282b87d6b4b1802916af3525af63a7d4d012439ca46a33e0ea27de790b685a9cd826606",
				"x": "56be8367447e33cb1a05ac18ecfca8b0b2621e832d4be652f45fa35ceea66de01b8a5f79e44f0264032b60ad6c19f6fbb08180a8486c7b05096dc1169d26700f",
				"a handshake challenge of the usual length, 32b": "b07422d49a2891c8e4b95d0e364a9b7f173380608edaed356eba0e00d72f752eb38d3801ff2d487c239db05cf324606b9913d6dc899d619c8f1b37f58c28430f",
				"\x00\x01\x02 binary \xff\xfe":                   "b6c009e7b71f8b89c9332fbd4769b8af58e45af90b989cbdaa7fde5ff99727b34d11b3b6ecdf3092e54757a512ab597f8b7556c3497277e9c29ad7ef8120b00d",
			},
		},
		{
			privateKey: "OHLIlXAE0ZCu2dKqPXvmFfLhuFqglcWIOHOduNmpCWVDSx3cDfRvF3KBz6r+j7oBBHk5iNq3xGgamDyQLSQLHw==",
			publicKey:  "7a79728742b846356834dbe6f8031994efd4c5f4125d893fc890b72d1bd54a86",
			onionID:    "pj4xfb2cxbddk2bu3ptpqayzstx5jrpucjoysp6isc3s2g6vjkdobkqd",
			signatures: map[string]string{
				"":  "29f4a28e83e8c9a9fd18044b3d21319e384f512bdb20839c048f4f8154d296e90e07d1af00b4ca44aecdace48fac8a3e2cc1b0aa51bb4a0adaa2bf78a775770e",
				"x": "1b447c570b9b0fd31d63a233b9a84c8148345aa79d64c19f73749eee85e7e9f88e942f41f1e4c706248ea82e2b88c28923f5ac290de419830e37645154eb8f04",
				"a handshake challenge of the usual length, 32b": "f9d45e83084c6d4646c34dded4df20241a6333d22bdd84a0d034b648979686908a5da365ddcf16487794bf42db0ba1dc1c8c8d20c552a8cf6b40f591c55ad506",
				"\x00\x01\x02 binary \xff\xfe":                   "f301c80cc5253ec7f138f7db6b6a46e6ef8405b27ddf249e8442bc7ed2d532745c5b2d60433132070294cdf94666a1cf7b34f4aa8f4da045bfc35b5c4e06d10c",
			},
		},
		{
			privateKey: "SLStvDIlV7hV3J8EHRTz2Ah4qVcUa+twdGV78KuoHWhkD91E4m1LqE03oL2/yvlJjmqpdZ/4aY5ZdnOgbOycFw==",
			publicKey:  "9d8ad60b1bdcdbfc37ed20023999d1de3697b908c5cc06271ed882a7b7ce320a",
			onionID:    "twfnmcy33tn7yn7neabdtgor3y3jpoiiyxgamjy63cbkpn6ogiffg4qd",
			signatures: map[string]string{
				"":  "e0cfa291cc5980ec442083a888a4f07630dc09c979448e2accd65292ccf0c9df14d005cb4ea71611de59bcd209fb160b5fa30f6da06493ba397d9949f93f7708",
				"x": "8afe76271d73f40acc4f101dd5287f7141bbdf507f6495e45ee8b8cdac14dde54f438d7503a0f8ac48582ec76b3709810245c351032cbae9856ba5b72676d30e",
				"a handshake challenge of the usual length, 32b": "faae17d1df2fa66af3f916fb916e75c9ede938812406049750ed938644fdc4c43ceaf450533fad10f93a637eeb6846ae89f2980efda7f08ca985c1835ed1d706",
				"\x00\x01\x02 binary \xff\xfe":                   "b60e6a57e1b1d9df5eae2c59da9cb4a16d1b7075db02707f86a672126f4708a18b17953fe09d8653a1c6d1c86f5d3d3981370a968cee9495cd6126515f23dd00",
			},
		},
	}
	return vectors
}

// The public half must be recoverable from a stored private key alone, which
// is how a caller derives its address before any client is running.
func TestPublicKeyFromPrivateMatchesReference(t *testing.T) {
	for _, v := range compatibilityVectors() {
		priv, want := v.decode(t)

		got, err := PublicKeyFromPrivate(priv)
		if err != nil {
			t.Fatalf("PublicKeyFromPrivate: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("public key for %s:\n got %x\nwant %x", v.onionID, got, want)
		}
	}
}

func TestOnionIDMatchesReference(t *testing.T) {
	for _, v := range compatibilityVectors() {
		_, pub := v.decode(t)

		got, err := OnionIDFromPublicKey(pub)
		if err != nil {
			t.Fatalf("OnionIDFromPublicKey: %v", err)
		}
		if got != v.onionID {
			t.Errorf("onion id = %q, want %q", got, v.onionID)
		}
	}
}

func TestPublicKeyFromOnionIDMatchesReference(t *testing.T) {
	for _, v := range compatibilityVectors() {
		_, want := v.decode(t)

		got, err := PublicKeyFromOnionID(v.onionID)
		if err != nil {
			t.Fatalf("PublicKeyFromOnionID: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("public key for %s does not round trip", v.onionID)
		}

		// The ".onion" suffix is what callers usually have in hand.
		got, err = PublicKeyFromOnionID(v.onionID + ".onion")
		if err != nil {
			t.Fatalf("PublicKeyFromOnionID with suffix: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("public key for %s does not round trip with suffix", v.onionID)
		}
	}
}

// Signatures must be byte-identical to the reference: peers verify them
// against a key derived from an onion address, so a different-but-valid
// signature would break handshakes between old and new builds.
func TestSignMatchesReference(t *testing.T) {
	for _, v := range compatibilityVectors() {
		priv, pub := v.decode(t)

		for message, expected := range v.signatures {
			want, err := hex.DecodeString(expected)
			if err != nil {
				t.Fatalf("decode signature: %v", err)
			}

			got, err := Sign(priv, []byte(message))
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("signature over %q for %s:\n got %x\nwant %x",
					message, v.onionID, got, want)
			}
			if !Verify(pub, []byte(message), got) {
				t.Errorf("our own signature over %q failed to verify", message)
			}
		}
	}
}

// The reverse direction: a reference signature must verify for us, which is
// what happens when an older peer talks to a newer one.
func TestVerifyAcceptsReferenceSignatures(t *testing.T) {
	for _, v := range compatibilityVectors() {
		pub, err := PublicKeyFromOnionID(v.onionID)
		if err != nil {
			t.Fatalf("PublicKeyFromOnionID: %v", err)
		}
		for message, expected := range v.signatures {
			sig, err := hex.DecodeString(expected)
			if err != nil {
				t.Fatalf("decode signature: %v", err)
			}
			if !Verify(pub, []byte(message), sig) {
				t.Errorf("reference signature over %q did not verify", message)
			}
			if Verify(pub, []byte(message+"tampered"), sig) {
				t.Errorf("verification accepted a signature over the wrong message")
			}
		}
	}
}

// A generated key must survive a round trip through the stored format, which
// is what keeps a newly created service reachable after a restart.
func TestGeneratedKeyRoundTrips(t *testing.T) {
	for _, v := range compatibilityVectors() {
		priv, _ := v.decode(t)

		pub, err := PublicKeyFromPrivate(priv)
		if err != nil {
			t.Fatalf("PublicKeyFromPrivate: %v", err)
		}
		id, err := OnionIDFromPublicKey(pub)
		if err != nil {
			t.Fatalf("OnionIDFromPublicKey: %v", err)
		}
		recovered, err := PublicKeyFromOnionID(id)
		if err != nil {
			t.Fatalf("PublicKeyFromOnionID: %v", err)
		}
		if !bytes.Equal(recovered, pub) {
			t.Errorf("key does not survive the round trip for %s", v.onionID)
		}
		if len(id) != 56 {
			t.Errorf("address is %d chars, want 56", len(id))
		}
	}
}

func TestRejectsMalformedInput(t *testing.T) {
	if _, err := OnionIDFromPublicKey([]byte{1, 2, 3}); err == nil {
		t.Error("expected an error for a short public key")
	}
	if _, err := PublicKeyFromPrivate([]byte{1, 2, 3}); err == nil {
		t.Error("expected an error for a short private key")
	}
	if _, err := Sign([]byte{1, 2, 3}, []byte("x")); err == nil {
		t.Error("expected an error for a short private key")
	}
	if _, err := PublicKeyFromOnionID("not an onion id"); err == nil {
		t.Error("expected an error for a malformed id")
	}

	// A valid address with one character changed must fail the checksum rather
	// than silently yielding a different key.
	id := []byte(compatibilityVectors()[0].onionID)
	if id[0] == 'a' {
		id[0] = 'b'
	} else {
		id[0] = 'a'
	}
	if _, err := PublicKeyFromOnionID(string(id)); err == nil {
		t.Error("expected a checksum failure for a corrupted id")
	}
}
