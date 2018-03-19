package dns

import (
	"context"
	"net"
	"testing"
)

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
}
