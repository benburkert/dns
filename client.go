package dns

import (
	"context"
	"net"
	"sync/atomic"
)

// Client is a DNS client.
type Client struct {
	// Transport manages connections to DNS servers.
	Transport AddrDialer

	id uint32
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
	id := query.ID

	msg := *query.Message
	msg.ID = c.nextID()

	if err := conn.Send(&msg); err != nil {
		return nil, err
	}

	if err := conn.Recv(&msg); err != nil {
		return nil, err
	}
	msg.ID = id

	return &msg, nil
}

const idMask = (1 << 16) - 1

func (c *Client) nextID() int {
	return int(atomic.AddUint32(&c.id, 1) & idMask)
}
