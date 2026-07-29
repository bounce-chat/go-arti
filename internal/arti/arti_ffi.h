/* C ABI exported by rust/arti-ffi.
 *
 * Conventions:
 *   - Handles are opaque and must be released with arti_client_free().
 *   - Structured values cross as JSON strings; free them with
 *     arti_string_free(). NULL means "nothing", not "error", unless the
 *     function also takes an err_out.
 *   - Fallible calls take an err_out; on failure they return NULL or -1 and
 *     store an owned message there, which the caller frees with
 *     arti_string_free().
 *   - arti_version() returns a static string that must NOT be freed.
 */

#ifndef ARTI_FFI_H
#define ARTI_FFI_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct arti_client arti_client_t;

/* Version of Arti backing this library, e.g. "Arti 0.44". Statically
 * allocated; do not free. */
const char *arti_version(void);

/* Create a client from a JSON configuration blob. NULL on failure. */
arti_client_t *arti_client_new(const char *config_json, char **err_out);

/* Start listeners and background tasks. Returns 0 on success, -1 on failure.
 * Does not block. */
int arti_client_start(arti_client_t *client, char **err_out);

/* Block until the client is shut down. Returns 0, or -1 on a NULL handle. */
int arti_client_wait(arti_client_t *client);

/* Ask the client to stop, unblocking arti_client_wait(). */
void arti_client_shutdown(arti_client_t *client);

/* Release a client handle. Implies shutdown. */
void arti_client_free(arti_client_t *client);

/* Current bootstrap phase as JSON:
 *   {"progress":<0-100>,"tag":"...","summary":"..."} */
char *arti_bootstrap_status(arti_client_t *client);

/* Enable (non-zero) or disable (zero) use of the Tor network.
 * Returns 0 on success, -1 on failure. */
int arti_set_network_enabled(arti_client_t *client, int enabled, char **err_out);

/* 1 if the network is enabled, 0 if not, -1 on a NULL handle. */
int arti_network_enabled(arti_client_t *client);

/* SOCKS listener address as "host:port", or NULL if none is running. */
char *arti_socks_addr(arti_client_t *client);

/* Launch an onion service. Request JSON:
 *   {"key_type":"NEW"|"ED25519-V3","key_blob":"BEST"|<base64>,
 *    "ports":[{"virtual_port":80,"target":"127.0.0.1:8080"}],
 *    "discard_pk":false}
 * Response JSON:
 *   {"service_id":"<base32>","secret_key":"<base64>"}   (secret_key omitted
 *                                                        when discarded) */
char *arti_onion_add(arti_client_t *client, const char *req_json, char **err_out);

/* Tear down a service previously created by arti_onion_add().
 * Returns 0 on success, -1 on failure. */
int arti_onion_del(arti_client_t *client, const char *service_id, char **err_out);

/* Wait up to timeout_ms for the next asynchronous event, returned as JSON:
 *   {"type":"status_client","progress":N,"tag":"...","summary":"..."}
 *   {"type":"hs_desc","action":"UPLOAD"|"UPLOADED"|"FAILED",
 *    "address":"...","reason":"..."}
 * Returns NULL if no event arrived in time. */
char *arti_next_event(arti_client_t *client, int timeout_ms);

/* Start collecting Arti's log records at the given EnvFilter directives.
 * Returns 0 if installed, -1 if a subscriber was already present.
 * Process-wide: tracing permits only one subscriber. */
int arti_log_enable(const char *directives);

/* Wait up to timeout_ms for the next log record, as JSON:
 *   {"level":"INFO","target":"tor_dirmgr","message":"..."}
 * Returns NULL if none arrived in time. */
char *arti_next_log(int timeout_ms);

/* Derive the 32-byte public key from a 64-byte expanded secret key.
 * Writes 32 bytes to out. Returns 0 on success, -1 on failure. */
int arti_public_key(const unsigned char *secret, size_t secret_len, unsigned char *out);

/* Sign a message with a 64-byte expanded ed25519 secret key.
 * Writes 64 bytes to out. Returns 0 on success, -1 on failure. */
int arti_sign(const unsigned char *secret, size_t secret_len,
              const unsigned char *message, size_t message_len,
              unsigned char *out);

/* Free a string returned by this library (but not arti_version()). */
void arti_string_free(char *s);

#ifdef __cplusplus
}
#endif

#endif /* ARTI_FFI_H */
