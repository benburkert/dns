package dns

import (
	"context"
	"net"
	"sync"
	"time"
)

// MessageWriter is used by a DNS handler to serve a DNS query.
type MessageWriter interface {
	// Authoritative sets the Authoritative Answer (AA) bit of the header.
	Authoritative(bool)
	// Recursion sets the Recursion Available (RA) bit of the header.
	Recursion(bool)
	// Status sets the Response code (RCODE) bits of the header.
	Status(RCode)

	// TTL sets the value for additional records.
	TTL(time.Duration)

	// Answer adds a record to the answers section.
	Answer(fqdn string, rr Record)
	// Authority adds a record to the authority section.
	Authority(fqdn string, rr Record)
	// Additional adds a record to the additional section
	Additional(fqdn string, rr Record)

	// Reply sends the response message.
	Reply(context.Context) error
}

type messageWriter struct {
	res *Message

	ttl time.Duration
}

func (w *messageWriter) Authoritative(aa bool) { w.res.Authoritative = aa }
func (w *messageWriter) Recursion(ra bool)     { w.res.RecursionAvailable = ra }
func (w *messageWriter) Status(rc RCode)       { w.res.RCode = rc }

func (w *messageWriter) TTL(ttl time.Duration) { w.ttl = ttl }

func (w *messageWriter) Answer(fqdn string, rec Record) {
	w.res.Answers = append(w.res.Answers, w.rr(fqdn, rec))
}

func (w *messageWriter) Authority(fqdn string, rec Record) {
	w.res.Authorities = append(w.res.Authorities, w.rr(fqdn, rec))
}

func (w *messageWriter) Additional(fqdn string, rec Record) {
	w.res.Additionals = append(w.res.Additionals, w.rr(fqdn, rec))
}

func (w *messageWriter) rr(fqdn string, rec Record) Resource {
	return Resource{
		Name:   fqdn,
		Class:  ClassIN,
		TTL:    w.ttl,
		Record: rec,
	}
}

type packetWriter struct {
	*messageWriter

	addr net.Addr
	conn net.PacketConn
}

func (w packetWriter) Reply(ctx context.Context) error {
	buf, err := w.res.Pack(nil, true)
	if err != nil {
		return err
	}

	_, err = w.conn.WriteTo(buf, w.addr)
	return err
}

type streamWriter struct {
	*messageWriter

	mu   *sync.Mutex
	conn net.Conn
}

func (w streamWriter) Reply(ctx context.Context) error {
	buf, err := w.res.Pack(make([]byte, 2), true)
	if err != nil {
		return err
	}

	blen := uint16(len(buf) - 2)
	if int(blen) != len(buf)-2 {
		return ErrOversizedMessage
	}
	nbo.PutUint16(buf[:2], blen)

	w.mu.Lock()
	defer w.mu.Unlock()

	_, err = w.conn.Write(buf)
	return err
}

type autoWriter struct {
	MessageWriter

	replied bool
}

func (w autoWriter) Reply(ctx context.Context) error {
	w.replied = true

	return w.MessageWriter.Reply(ctx)
}
