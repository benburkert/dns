package dns_test

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/benburkert/dns"
)

func ExampleClient_overrideNameServers() {
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,

		Dial: (&dns.Client{
			Transport: &dns.Transport{
				Proxy: dns.NameServers{
					&net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 53},
					&net.UDPAddr{IP: net.IPv4(8, 8, 4, 4), Port: 53},
				}.RoundRobin(),
			},
		}).Dial,
	}

	addrs, err := net.LookupHost("127.0.0.1.xip.io")
	if err != nil {
		panic(err)
	}

	for _, addr := range addrs {
		fmt.Println(addr)
	}
	// Output: 127.0.0.1
}

func ExampleClient_dnsOverTLS() {
	dnsLocal := dns.OverTLSAddr{
		Addr: &net.TCPAddr{
			IP:   net.IPv4(192, 168, 8, 8),
			Port: 853,
		},
	}

	client := &dns.Client{
		Transport: &dns.Transport{
			Proxy: dns.NameServers{dnsLocal}.Random(rand.Reader),

			TLSConfig: &tls.Config{
				ServerName: "dns.local",
			},
		},
	}

	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial:     client.Dial,
	}
}

func ExampleServer_authoritative() {
	customTLD := &dns.Zone{
		Origin: "tld.",
		TTL:    time.Hour,
		SOA: &dns.SOA{
			NS:     "dns.tld.",
			MBox:   "hostmaster.tld.",
			Serial: 1234,
		},
		RRs: map[string][]dns.Record{
			"1.app": []dns.Record{
				&dns.A{net.IPv4(10, 42, 0, 1).To4()},
				&dns.AAAA{net.ParseIP("dead:beef::1")},
			},
			"2.app": []dns.Record{
				&dns.A{net.IPv4(10, 42, 0, 2).To4()},
				&dns.AAAA{net.ParseIP("dead:beef::2")},
			},
			"3.app": []dns.Record{
				&dns.A{net.IPv4(10, 42, 0, 3).To4()},
				&dns.AAAA{net.ParseIP("dead:beef::3")},
			},
			"app": []dns.Record{
				&dns.A{net.IPv4(10, 42, 0, 1).To4()},
				&dns.A{net.IPv4(10, 42, 0, 2).To4()},
				&dns.A{net.IPv4(10, 42, 0, 3).To4()},
				&dns.AAAA{net.ParseIP("dead:beef::1")},
				&dns.AAAA{net.ParseIP("dead:beef::2")},
				&dns.AAAA{net.ParseIP("dead:beef::3")},
			},
		},
	}

	srv := &dns.Server{
		Addr:    ":5353",
		Handler: customTLD,
	}

	go srv.ListenAndServe(context.Background())
}
