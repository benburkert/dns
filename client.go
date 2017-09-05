package dns

import (
	"context"
	"net"
)

// Client is a DNS client.
type Client struct {
	// Transport manages connections to DNS servers.
	Transport AddrDialer
}

// Dial dials a DNS server and returns a net Conn that reads and writes DNS
// messages.
func (c *Client) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
		addr, err := net.ResolveTCPAddr(network, address)
		if err != nil {
			return nil, err
		}

		conn, err := c.dial(ctx, addr)
		if err != nil {
			return nil, err
		}

		return streamSession{
			session: &session{
				Conn:    conn,
				addr:    addr,
				client:  c,
				msgerrc: make(chan msgerr),
			},
		}, nil
	case "udp", "udp4", "udp6":

		addr, err := net.ResolveUDPAddr(network, address)
		if err != nil {
			return nil, err
		}

		conn, err := c.dial(ctx, addr)
		if err != nil {
			return nil, err
		}

		return packetSession{
			session: &session{
				Conn:    conn,
				addr:    addr,
				client:  c,
				msgerrc: make(chan msgerr),
			},
		}, nil
	default:
		return nil, ErrUnsupportedNetwork
	}
}

// Do sends a DNS query to a server and returns the response message.
func (c *Client) Do(ctx context.Context, query *Query) (*Message, error) {
	conn, err := c.dial(ctx, query.RemoteAddr)
	if err != nil {
		return nil, err
	}

	if t, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(t); err != nil {
			return nil, err
		}
	}

	return c.do(conn, query)
}

func (c *Client) dial(ctx context.Context, addr net.Addr) (Conn, error) {
	tport := c.Transport
	if tport == nil {
		tport = new(Transport)
	}

	return tport.DialAddr(ctx, addr)
}

func (c *Client) do(conn Conn, query *Query) (*Message, error) {
	if err := conn.Send(query.Message); err != nil {
		return nil, err
	}

	var msg Message
	if err := conn.Recv(&msg); err != nil {
		return nil, err
	}
	return &msg, nil
}
