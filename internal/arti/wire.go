package arti

// The shapes that cross the FFI boundary as JSON.
//
// These mirror the structs in rust/arti-ffi; the field tags are the contract,
// so a rename on either side has to be made on both.

// artiConfig is the configuration accepted by arti_client_new.
type artiConfig struct {
	// DataDirectory is where Arti keeps state and its directory cache.
	DataDirectory string `json:"data_directory"`
	// SocksPort is "auto", "disabled", or a port number.
	SocksPort string `json:"socks_port"`
	// SocksBindAddress is the interface the SOCKS listener binds.
	SocksBindAddress string `json:"socks_bind_address"`
	// DisableNetwork starts the client without connecting.
	DisableNetwork bool `json:"disable_network"`
	// UseBridges enables the configured bridges.
	UseBridges bool `json:"use_bridges"`
	// Bridges are torrc-style bridge lines. Never nil: a nil slice encodes as
	// null, and the backend expects a sequence.
	Bridges []string `json:"bridges"`
}

// bootstrapStatus mirrors the JSON reported by arti_bootstrap_status.
type bootstrapStatus struct {
	// Progress is bootstrap completion, 0-100.
	Progress int `json:"progress"`
	// Tag is a machine-readable phase name.
	Tag string `json:"tag"`
	// Summary describes the phase for a human.
	Summary string `json:"summary"`
	// Liveness is "up" or "down".
	Liveness string `json:"liveness"`
}

// onionPort is one virtual-to-local port mapping.
type onionPort struct {
	// VirtualPort is the port exposed on the onion address.
	VirtualPort uint16 `json:"virtual_port"`
	// Target is where to forward it, as host:port.
	Target string `json:"target"`
}

// onionAddRequest is the JSON accepted by arti_onion_add.
type onionAddRequest struct {
	// KeyType is "NEW" or "ED25519-V3".
	KeyType string `json:"key_type"`
	// KeyBlob is "BEST"/"ED25519-V3" for NEW, otherwise the base64 secret.
	KeyBlob string `json:"key_blob"`
	// Ports must have at least one entry.
	Ports []onionPort `json:"ports"`
	// DiscardPK suppresses the key in the response.
	DiscardPK bool `json:"discard_pk"`
}

// onionAddResponse is the JSON returned by arti_onion_add.
type onionAddResponse struct {
	// ServiceID is the onion address, without the ".onion" suffix.
	ServiceID string `json:"service_id"`
	// SecretKey is the base64 identity key, absent when discarded.
	SecretKey string `json:"secret_key"`
}

// artiEvent is the JSON returned by arti_next_event.
type artiEvent struct {
	// Type is "status_client" or "hs_desc".
	Type string `json:"type"`

	// Bootstrap progress, for "status_client".
	Progress int    `json:"progress"`
	Tag      string `json:"tag"`
	Summary  string `json:"summary"`

	// Onion service publication, for "hs_desc".
	Action  string `json:"action"`
	Address string `json:"address"`
	Reason  string `json:"reason"`
}

// encode renders a configuration for the FFI boundary.
func (c artiConfig) encode() (string, error) { return encodeJSON(c) }
