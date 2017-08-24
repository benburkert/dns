package dns

import (
	"context"
	"net"
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
	DialContext func(context.Context, string, string) (net.Conn, error)
}

// DialAddr dials a net Addr and returns a Conn.
func (d *Dialer) DialAddr(ctx context.Context, addr net.Addr) (Conn, error) {
	dial := d.DialContext
	if dial == nil {
		dial = DefaultDialer.DialContext
	}

	conn, err := dial(ctx, addr.Network(), addr.String())
	if err != nil {
		return nil, err
	}
	if conn, ok := conn.(Conn); ok {
		return conn, nil
	}

	switch addr.Network() {
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
