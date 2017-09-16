package dns

import (
	"bytes"
	"context"
	"net"
	"reflect"
	"testing"
	"time"
)

func TestServerListenAndServe(t *testing.T) {
	t.Parallel()

	localhost := net.IPv4(127, 0, 0, 1).To4()

	srv := mustServer(HandlerFunc(func(ctx context.Context, w MessageWriter, r *Query) {
		msg := r.Message
		msg.Answers = append(msg.Answers, Resource{
			Name:  "test.local.",
			Class: ClassINET,
			TTL:   60 * time.Second,
			Record: &A{
				A: localhost,
			},
		})

		w.Send(msg)
	}))

	addrUDP, err := net.ResolveUDPAddr("udp", srv.Addr)
	if err != nil {
		t.Fatal(err)
	}

	query := &Query{
		RemoteAddr: addrUDP,
		Message: &Message{
			Questions: []Question{
				{Name: "test.local.", Type: TypeA},
			},
		},
	}

	msgUDP, err := new(Client).Do(context.Background(), query)
	if err != nil {
		t.Fatal(err)
	}

	if want, got := localhost, msgUDP.Answers[0].Record.(*A).A.To4(); !bytes.Equal(want, got) {
		t.Errorf("want A record %q, got %q", want, got)
	}

	addrTCP, err := net.ResolveTCPAddr("tcp", srv.Addr)
	if err != nil {
		t.Fatal(err)
	}

	query.RemoteAddr = addrTCP

	msgTCP, err := new(Client).Do(context.Background(), query)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(msgUDP, msgTCP) {
		t.Error("UDP and TCP messages did not match")
	}
}

func mustServer(handler Handler) *Server {
	srv := &Server{
		Addr:    mustUnusedAddr(),
		Handler: handler,
	}

	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		panic(err)
	}

	conn, err := net.ListenPacket("udp", srv.Addr)
	if err != nil {
		panic(err)
	}

	go srv.Serve(context.Background(), ln)
	go srv.ServePacket(context.Background(), conn)

	return srv
}

func mustUnusedAddr() string {
	for {
		lnTCP, err := net.Listen("tcp", ":0")
		if err != nil {
			panic(err)
		}

		lnUDP, err := net.ListenPacket("udp", lnTCP.Addr().String())
		if err != nil {
			if err := lnTCP.Close(); err != nil {
				panic(err)
			}
			continue
		}

		if err := lnTCP.Close(); err != nil {
			panic(err)
		}
		if err := lnUDP.Close(); err != nil {
			panic(err)
		}

		return lnTCP.Addr().String()
	}
}
