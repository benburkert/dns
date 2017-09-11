package dns

import (
	"context"
	"net"
	"reflect"
	"testing"
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

	srv := &testServer{
		Answers: map[Question]Resource{
			Question{
				Name:  "localhost.dev.",
				Type:  TypeA,
				Class: ClassINET,
			}: Resource{
				Name:  "localhost.dev.",
				Class: ClassINET,
				TTL:   60,
				Record: &A{
					A: net.IPv4(127, 0, 0, 1),
				},
			},
			Question{
				Name:  "localhost.dev.",
				Type:  TypeAAAA,
				Class: ClassINET,
			}: Resource{
				Name:  "localhost.dev.",
				Class: ClassINET,
				TTL:   60,
				Record: &AAAA{
					AAAA: net.ParseIP("::1"),
				},
			},
		},
	}

	conn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		t.Fatal(err)
	}

	if err := srv.StartUDP(conn); err != nil {
		t.Fatal(err)
	}

	client := &Client{
		Transport: &Transport{
			Proxy: func(_ context.Context, _ net.Addr) (net.Addr, error) {
				return conn.LocalAddr(), nil
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
