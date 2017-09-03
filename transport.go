package dns

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
)

// Transport is an implementation of AddrDialer that manages connections to DNS
// servers. Transport may modify the sending and recieving of messages but does
// not modify messages.
type Transport struct {
	TLSConfig *tls.Config // optional TLS config, used by DialAddr

	// DialContext func creates the underlying net connection. The DialContext
	// method of a new net.Dialer is used by default.
	DialContext func(context.Context, string, string) (net.Conn, error)
}

var defaultDialer = &net.Dialer{
	Resolver: &net.Resolver{},
}

// DialAddr dials a net Addr and returns a Conn.
func (t *Transport) DialAddr(ctx context.Context, addr net.Addr) (Conn, error) {
	dial := t.DialContext
	if dial == nil {
		dial = defaultDialer.DialContext
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
		if t.TLSConfig != nil {
			cfg = t.TLSConfig.Clone()
		}

		conn = tls.Client(conn, cfg)
		if err := conn.(*tls.Conn).Handshake(); err != nil {
			return nil, err
		}
	}

	if _, ok := conn.(net.PacketConn); ok {
		return &PacketConn{
			Conn: conn,
		}, nil
	}
	return &StreamConn{
		Conn: conn,
	}, nil
}
