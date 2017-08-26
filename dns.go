package dns

import (
	"errors"
	"net"
)

var (
	// ErrOversizedQuery is an error returned when attempting to send a query that
	// is longer than the maximum allowed number of bytes.
	ErrOversizedQuery = errors.New("oversized query")

	// ErrUnsupportedNetwork is returned when DialAddr is called with an
	// unknown network.
	ErrUnsupportedNetwork = errors.New("unsupported network")
)

// Query is a DNS request message bound for a DNS resolver.
type Query struct {
	*Message

	// RemoteAddr is the address of a DNS resolver.
	RemoteAddr net.Addr
}

// OverTLSAddr indicates the remote DNS service implements DNS-over-TLS as
// defined in RFC 7858.
type OverTLSAddr struct {
	net.Addr
}

// Network returns the address's network name with a "-tls" suffix.
func (a OverTLSAddr) Network() string {
	return a.Addr.Network() + "-tls"
}
