package dns

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
)

// DefaultDialer is the default implementation of Dialer. It establishes a
// connection to a remote address and returns a Conn suitable for sending and
// receiving DNS messages.
var DefaultDialer = &Dialer{
	DialContext: (&net.Dialer{
		Resolver: &net.Resolver{},
	}).DialContext,
}

// Dialer connects to a DNS resolver specified by a net Addr.
type Dialer struct {
	// DialContext func creates the underlying net connection. The DialContext
	// method of a new net.Dialer is used by default.
	DialContext func(context.Context, string, string) (net.Conn, error)

	TLSConfig *tls.Config // optional TLS config, used by DialAddr
}

// DialAddr dials a net Addr and returns a Conn.
func (d *Dialer) DialAddr(ctx context.Context, addr net.Addr) (Conn, error) {
	dial := d.DialContext
	if dial == nil {
		dial = DefaultDialer.DialContext
	}

	network, dnsOverTLS := addr.Network(), false
	if strings.HasSuffix(network, "-tls") {
		network, dnsOverTLS = network[:len(network)-4], true
	}

	conn, err := dial(ctx, network, addr.String())
	if err != nil {
		return nil, err
	}
	if conn, ok := conn.(Conn); ok {
		return conn, nil
	}

	if _, ok := conn.(*tls.Conn); dnsOverTLS && !ok {
		ipaddr, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			return nil, err
		}

		cfg := &tls.Config{ServerName: ipaddr}
		if d.TLSConfig != nil {
			cfg = d.TLSConfig.Clone()
		}

		conn = tls.Client(conn, cfg)
		if err := conn.(*tls.Conn).Handshake(); err != nil {
			return nil, err
		}
	}

	switch network {
	case "tcp", "tcp4", "tcp6":
		return &StreamConn{
			Conn: conn,
		}, nil
	case "udp", "udp4", "udp6":
		return &PacketConn{
			Conn: conn,
		}, nil
	default:
		return nil, ErrUnsupportedNetwork
	}
}
