package dns

import (
	"context"
	"net"
	"testing"
)

func TestPacketSession(t *testing.T) {
	t.Parallel()

	srv := mustServer(localhostZone)

	addr, err := net.ResolveTCPAddr("tcp", srv.Addr)
	if err != nil {
		t.Fatal(err)
	}

	conn, err := new(Transport).DialAddr(context.Background(), addr)
	if err != nil {
		t.Fatal(err)
	}

	ps := &packetSession{
		session: session{
			Conn:    conn,
			addr:    addr,
			client:  new(Client),
			msgerrc: make(chan msgerr),
		},
	}

	msg := new(Message)
	for i := 0; i < 120; i++ {
		q := Question{
			Name:  "app.localhost.",
			Type:  TypeA,
			Class: ClassIN,
		}

		msg.Questions = append(msg.Questions, q)
	}

	buf, err := msg.Pack(nil, true)
	if _, err := ps.Write(buf); err != nil {
		t.Fatal(err)
	}

	// test truncate due to short buffer size

	if _, err := ps.Write(buf); err != nil {
		t.Fatal(err)
	}

	buf = make([]byte, 100)
	if _, err := ps.Read(buf); err != nil {
		t.Fatal(err)
	}

	_, err = msg.Unpack(buf)
	if want, got := errResourceLen, err; want != got {
		t.Fatalf("want %v error, got %v", want, got)
	}
	if want, got := true, msg.Truncated; want != got {
		t.Errorf("response message was not truncated")
	}
}

func TestStreamSession(t *testing.T) {
	t.Parallel()

	srv := mustServer(localhostZone)

	addr, err := net.ResolveTCPAddr("tcp", srv.Addr)
	if err != nil {
		t.Fatal(err)
	}

	conn, err := new(Transport).DialAddr(context.Background(), addr)
	if err != nil {
		t.Fatal(err)
	}

	ss := &streamSession{
		session: session{
			Conn:    conn,
			addr:    addr,
			client:  new(Client),
			msgerrc: make(chan msgerr),
		},
	}

	msg := &Message{
		Questions: []Question{
			{
				Name:  "app.localhost.",
				Type:  TypeA,
				Class: ClassIN,
			},
		},
	}

	buf, err := msg.Pack(nil, true)
	if err != nil {
		t.Fatal(err)
	}
	buf = append(make([]byte, 2), buf...)
	nbo.PutUint16(buf[:2], uint16(len(buf)-2))

	if _, err := ss.Write(buf); err != nil {
		t.Fatal(err)
	}

	// test 2 byte length prefix read followed by msg read

	if _, err := ss.Read(buf[:2]); err != nil {
		t.Fatal(err)
	}
	mlen := nbo.Uint16(buf[:2])

	buf = make([]byte, mlen)
	if _, err := ss.Read(buf); err != nil {
		t.Fatal(err)
	}

	if buf, err = msg.Unpack(buf); err != nil {
		t.Fatal(err)
	}
	if want, got := 0, len(buf); want != got {
		t.Errorf("want %d extra buffer bytes, got %d", want, got)
	}
}
