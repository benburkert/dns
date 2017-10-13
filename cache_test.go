package dns

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestCache(t *testing.T) {
	cache := new(Cache)
	client := &Client{
		Resolver: cache,
	}

	localhost := net.IPv4(127, 0, 0, 1).To4()
	ipc := make(chan net.IP, 1)
	ipc <- localhost

	srv := mustServer(HandlerFunc(func(ctx context.Context, w MessageWriter, r *Query) {
		w.Answer("test.local.", time.Minute, &A{A: <-ipc})
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

	msg, err := client.Do(context.Background(), query)
	if err != nil {
		t.Fatal(err)
	}

	if want, got := localhost, msg.Answers[0].Record.(*A).A.To4(); !want.Equal(got) {
		t.Errorf("want A record %q, got %q", want, got)
	}

	ipc <- net.IPv4(255, 255, 255, 255).To4()

	if msg, err = client.Do(context.Background(), query); err != nil {
		t.Fatal(err)
	}

	if want, got := localhost, msg.Answers[0].Record.(*A).A.To4(); !want.Equal(got) {
		t.Errorf("want A record %q, got %q", want, got)
	}
}
