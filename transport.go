package dns

import (
	"context"
	"net"
)

// Transport is an implementation of RoundTripper that supports DNS.
type Transport struct {
	// DialAddr specifies the dial function for creating a connection to a DNS
	// resolver.
	DialAddr func(context.Context, net.Addr) (Conn, error)
}

// RoundTrip implements the RoundTripper interface.
func (t *Transport) RoundTrip(ctx context.Context, query *Query) (*Message, error) {
	dial := t.DialAddr
	if dial == nil {
		dial = DefaultDialer.DialAddr
	}

	conn, err := dial(ctx, query.RemoteAddr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := conn.Send(query.Message); err != nil {
		return nil, err
	}

	msg := new(Message)
	return msg, conn.Recv(msg)
}
