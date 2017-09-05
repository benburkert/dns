package dns

import (
	"io"
	"net"
)

// Conn is a network connection to a DNS resolver.
type Conn interface {
	net.Conn

	// Recv reads a DNS message from the connection.
	Recv(msg *Message) error

	// Send writes a DNS message to the connection.
	Send(msg *Message) error
}

// PacketConn is a packet-oriented network connection to a DNS resolver that
// expects transmitted messages to adhere to RFC 1035 Section 4.2.1. "UDP
// usage".
type PacketConn struct {
	net.Conn

	rbuf, wbuf []byte
}

// Recv reads a DNS message from the underlying connection.
func (c *PacketConn) Recv(msg *Message) error {
	if len(c.rbuf) != 512 {
		c.rbuf = make([]byte, 512)
	}

	n, err := c.Read(c.rbuf)
	if err != nil {
		return err
	}

	return msg.Unpack(c.rbuf[:n])
}

// Send writes a DNS message to the underlying connection.
func (c *PacketConn) Send(msg *Message) error {
	if len(c.wbuf) != 512 {
		c.wbuf = make([]byte, 512)
	}

	var err error
	if c.wbuf, err = msg.AppendPack(c.wbuf[:0]); err != nil {
		return err
	}

	if len(c.wbuf) > 512 {
		return ErrOversizedQuery
	}

	_, err = c.Write(c.wbuf)
	return err
}

// StreamConn is a stream-oriented network connection to a DNS resolver that
// expects transmitted messages to adhere to RFC 1035 Section 4.2.2. "TCP
// usage".
type StreamConn struct {
	net.Conn

	rbuf, wbuf []byte
}

// Recv reads a DNS message from the underlying connection.
func (c *StreamConn) Recv(msg *Message) error {
	if len(c.rbuf) < 2 {
		c.rbuf = make([]byte, 1280)
	}

	if _, err := io.ReadFull(c, c.rbuf[:2]); err != nil {
		return err
	}

	l := int(c.rbuf[0])<<8 | int(c.rbuf[1])
	if len(c.rbuf) < l {
		c.rbuf = make([]byte, l)
	}

	if len(c.rbuf) < l {
		c.rbuf = make([]byte, l)
	}

	if _, err := io.ReadFull(c, c.rbuf[:l]); err != nil {
		return err
	}

	err := msg.Unpack(c.rbuf[:l])
	return err
}

// Send writes a DNS message to the underlying connection.
func (c *StreamConn) Send(msg *Message) error {
	if len(c.wbuf) < 2 {
		c.wbuf = make([]byte, 1024)
	}

	b, err := msg.AppendPack(c.wbuf[2:2])
	if err != nil {
		return err
	}
	c.wbuf[0], c.wbuf[1] = byte(len(b)>>8), byte(len(b))

	_, err = c.Write(c.wbuf[:len(b)+2])
	return err
}
