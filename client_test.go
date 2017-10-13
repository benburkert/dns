package dns

import (
	"context"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestLookupHost(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string

		host string

		addrs []string
		err   error
	}{
		{
			name: "dual-ipv-lookup",

			host: "localhost.dev",

			addrs: []string{"::1", "127.0.0.1"},
		},
	}

	srv := mustServer(&answerHandler{
		Answers: map[Question]Record{
			{
				Name:  "localhost.dev.",
				Type:  TypeA,
				Class: ClassIN,
			}: &A{
				A: net.IPv4(127, 0, 0, 1),
			},
			{
				Name:  "localhost.dev.",
				Type:  TypeAAAA,
				Class: ClassIN,
			}: &AAAA{
				AAAA: net.ParseIP("::1"),
			},
		},
	})

	addr, err := net.ResolveUDPAddr("udp", srv.Addr)
	if err != nil {
		t.Fatal(err)
	}

	client := &Client{
		Transport: &Transport{
			Proxy: func(_ context.Context, _ net.Addr) (net.Addr, error) {
				return addr, nil
			},
		},
	}

	rlv := &net.Resolver{
		PreferGo: true,
		Dial:     client.Dial,
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			addrs, err := rlv.LookupHost(context.Background(), test.host)
			if err != nil {
				t.Fatal(err)
			}

			if want, got := test.addrs, addrs; !reflect.DeepEqual(want, got) {
				t.Errorf("want LookupHost addrs %q, got %q", want, got)
			}
		})
	}
}

func TestClientResolver(t *testing.T) {
	t.Parallel()

	localhost := net.IPv4(127, 0, 0, 1).To4()
	goog := net.IPv4(8, 8, 8, 8).To4()

	client := &Client{
		Resolver: HandlerFunc(func(ctx context.Context, w MessageWriter, r *Query) {
			fqdn := r.Questions[0].Name
			if !strings.HasSuffix(fqdn, ".local.") {
				w.Recur(ctx)
				return
			}

			w.Answer(fqdn, time.Minute, &A{A: localhost})
		}),
	}

	srv := mustServer(HandlerFunc(func(ctx context.Context, w MessageWriter, r *Query) {
		fqdn := r.Questions[0].Name

		w.Answer(fqdn, time.Minute, &A{A: goog})
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

	query.Questions[0] = Question{Name: "test.goog.", Type: TypeA}
	if msg, err = client.Do(context.Background(), query); err != nil {
		t.Fatal(err)
	}

	if want, got := goog, msg.Answers[0].Record.(*A).A.To4(); !want.Equal(got) {
		t.Errorf("want A record %q, got %q", want, got)
	}
}
