package dns

import (
	"context"
	"errors"
	mathrand "math/rand"
	"net"
	"testing"
)

var testNameServers = NameServers{
	&net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 53},
	&net.UDPAddr{IP: net.IPv4(8, 8, 4, 4), Port: 53},
	&net.TCPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 53},
	&net.TCPAddr{IP: net.IPv4(8, 8, 4, 4), Port: 53},
}

func TestNamserverRoundRobin(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string

		proxyfn ProxyFunc
		addr    net.Addr

		addrs []net.Addr
		err   error
	}{
		{
			name: "round-robin-udp",

			proxyfn: testNameServers.RoundRobin(),
			addr:    new(net.UDPAddr),

			addrs: []net.Addr{
				&net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 53},
				&net.UDPAddr{IP: net.IPv4(8, 8, 4, 4), Port: 53},
				&net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 53},
				&net.UDPAddr{IP: net.IPv4(8, 8, 4, 4), Port: 53},
			},
		},
		{
			name: "random-tcp",

			proxyfn: testNameServers.Random(mathrand.New(mathrand.NewSource(0))),
			addr:    new(net.TCPAddr),

			addrs: []net.Addr{
				&net.TCPAddr{IP: net.IPv4(8, 8, 4, 4), Port: 53},
				&net.TCPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 53},
				&net.TCPAddr{IP: net.IPv4(8, 8, 4, 4), Port: 53},
			},
		},
		{
			name: "unknown-network",

			proxyfn: testNameServers.RoundRobin(),
			addr:    new(net.IPAddr),

			err:   errors.New("no nameservers for network: ip"),
			addrs: make([]net.Addr, 1),
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			for i, expected := range test.addrs {
				addr, err := test.proxyfn(context.Background(), test.addr)
				if test.err != nil {
					if want, got := test.err.Error(), err.Error(); want != got {
						t.Fatalf("want error %q, got %q", want, got)
					}
					continue
				}

				if err != nil {
					t.Fatal(err)
				}

				if want, got := expected.Network(), addr.Network(); want != got {
					t.Errorf("want %d network %v, got %v", i, want, got)
				}
				if want, got := expected.String(), addr.String(); want != got {
					t.Errorf("want %d address %v, got %v", i, want, got)
				}
			}
		})
	}
}
