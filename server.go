package dns

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"sync"
)

// MessageWriter is used by a DNS handler to respond to a DNS query.
type MessageWriter interface {
	Send(*Message) error
}

// Handler responds to a DNS query.
type Handler interface {
	ServeDNS(context.Context, MessageWriter, *Query)
}

// The HandlerFunc type is an adapter to allow the use of ordinary functions as
// DNS handlers. If f is a function with the appropriate signature,
// HandlerFunc(f) is a Handler that calls f.
type HandlerFunc func(context.Context, MessageWriter, *Query)

// ServeDNS calls f(w, r).
func (f HandlerFunc) ServeDNS(ctx context.Context, w MessageWriter, r *Query) {
	f(ctx, w, r)
}

// A Server defines parameters for running a DNS server. The zero value for
// Server is a valid configuration.
type Server struct {
	Addr      string      // TCP and UDP address to listen on, ":domain" if empty
	Handler   Handler     // handler to invoke
	TLSConfig *tls.Config // optional TLS config, used by ListenAndServeTLS
}

// ListenAndServe listens on both the TCP and UDP network address s.Addr and
// then calls Serve or ServePacket to handle queries on incoming connections.
// If srv.Addr is blank, ":domain" is used. ListenAndServe always returns a
// non-nil error.
func (s *Server) ListenAndServe(ctx context.Context) error {
	addr := s.Addr
	if addr == "" {
		addr = ":domain"
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}

	errc := make(chan error, 1)
	go func() { errc <- s.Serve(ctx, ln) }()
	go func() { errc <- s.ServePacket(ctx, conn) }()

	return <-errc
}

// ListenAndServeTLS listens on the TCP network address s.Addr and then calls
// Serve to handle requests on incoming TLS connections.
//
// If s.Addr is blank, ":853" is used.
//
// ListenAndServeTLS always returns a non-nil error.
func (s *Server) ListenAndServeTLS(ctx context.Context) error {
	addr := s.Addr
	if addr == "" {
		addr = ":domain"
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	return s.ServeTLS(ctx, ln)
}

// Serve accepts incoming connections on the Listener ln, creating a new
// service goroutine for each. The service goroutines read TCP encoded queries
// and then call s.Handler to reply to them.
//
// See RFC 1035, section 4.2.2 "TCP usage" for transport encoding of messages.
//
// Serve always returns a non-nil error.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}

		go s.serveStream(ctx, conn)
	}
}

// ServePacket reads UDP encoded queries from the PacketConn conn, creating a
// new service goroutine for each. The service goroutines call s.Handler to
// reply.
//
// See RFC 1035, section 4.2.1 "UDP usage" for transport encoding of messages.
//
// ServePacket always returns a non-nil error.
func (s *Server) ServePacket(ctx context.Context, conn net.PacketConn) error {
	defer conn.Close()

	for {
		buf := make([]byte, 512)
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return err
		}

		req := &Query{
			Message:    new(Message),
			RemoteAddr: addr,
		}

		if buf, err = req.Message.Unpack(buf[:n]); err != nil {
			log.Printf(err.Error())
			continue
		}
		if len(buf) != 0 {
			log.Printf("malformed packet, extra message bytes")
			continue
		}

		pw := packetWriter{
			conn: conn,
			addr: addr,
			req:  req,
		}

		go s.Handler.ServeDNS(ctx, pw, req)
	}
}

// ServeTLS accepts incoming connections on the Listener ln, creating a new
// service goroutine for each. The service goroutines read TCP encoded queries
// over a TLS channel and then call s.Handler to reply to them, in another
// service goroutine.
//
// See RFC 7858, section 3.3 for transport encoding of messages.
//
// ServeTLS always returns a non-nil error.
func (s *Server) ServeTLS(ctx context.Context, ln net.Listener) error {
	ln = tls.NewListener(ln, s.TLSConfig.Clone())
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}

		go func(conn net.Conn) {
			if err := conn.(*tls.Conn).Handshake(); err != nil {
				log.Printf(err.Error())
				return
			}

			s.serveStream(ctx, conn)
		}(conn)
	}
}

func (s *Server) serveStream(ctx context.Context, conn net.Conn) {
	var (
		rbuf = bufio.NewReader(conn)

		lbuf [2]byte
		mu   sync.Mutex
	)

	for {
		if _, err := rbuf.Read(lbuf[:]); err != nil {
			// TODO: check for timeout/temporary
			log.Printf(err.Error())
			return
		}

		buf := make([]byte, int(nbo.Uint16(lbuf[:])))
		if _, err := io.ReadFull(rbuf, buf); err != nil {
			log.Printf(err.Error())
			return
		}

		req := &Query{
			Message:    new(Message),
			RemoteAddr: conn.RemoteAddr(),
		}

		var err error
		if buf, err = req.Message.Unpack(buf); err != nil {
			log.Printf(err.Error())
			continue
		}
		if len(buf) != 0 {
			log.Printf("malformed packet, extra message bytes")
			continue
		}

		sw := streamWriter{
			mu:   &mu,
			conn: conn,
			req:  req,
		}

		go s.Handler.ServeDNS(ctx, sw, req)
	}
}

type packetWriter struct {
	conn net.PacketConn
	addr net.Addr

	req *Query
}

func (w packetWriter) Send(msg *Message) error {
	buf, err := msg.Pack(nil, true)
	if err != nil {
		return err
	}

	_, err = w.conn.WriteTo(buf, w.addr)
	return err
}

type streamWriter struct {
	mu *sync.Mutex

	conn net.Conn

	req *Query
}

func (w streamWriter) Send(msg *Message) error {
	buf, err := msg.Pack(make([]byte, 2), true)
	if err != nil {
		return err
	}

	blen := uint16(len(buf) - 2)
	if int(blen) != len(buf)-2 {
		return ErrOversizedMessage
	}
	nbo.PutUint16(buf[:2], blen)

	_, err = w.conn.Write(buf)
	return err
}
