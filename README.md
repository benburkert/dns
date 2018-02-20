# dns [![GoDoc](https://godoc.org/github.com/benburkert/dns?status.svg)](https://godoc.org/github.com/benburkert/dns) [![Build Status](https://travis-ci.org/benburkert/dns.svg)](https://travis-ci.org/benburkert/dns) [![Go Report Card](https://goreportcard.com/badge/github.com/benburkert/dns)](https://goreportcard.com/report/github.com/benburkert/dns)

DNS client and server package. [See godoc for details & examples.](https://godoc.org/github.com/benburkert/dns)

This fork adds a new Upstream() method to allow a caller to call a random DNS server selected from alternates (if any were provided).

### Example Usage:

```
	client := new(dns.Client)

	client.Transport = &dns.Transport{
		Proxy: dns.NameServers{
			&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53},
			&net.UDPAddr{IP: net.IPv4(8, 8, 4, 4), Port: 53},
		}.Upstream(rand.Reader),
	}

	// This is the http/s dialer
	dialer := &net.Dialer{
		Resolver: &net.Resolver{
			PreferGo: true,

			Dial: client.Dial,
		},
	}

  // Set a key telling us to select an alternate DNS server (8.8.4.4 in this case).
	ctx := context.Background()
	ctxupstream := context.WithValue(ctx, dns.UpstreamKey, 0)

	conn, err := dialer.DialContext(ctxupstream, "tcp", "example.com:80")

	if err != nil {
		t.Errorf("Error connecting to site: %s\n", err)
	}
  
	fmt.Fprintf(conn, "GET / HTTP/1.0\r\n\r\n")
	_, err = bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Errorf("Error reading http stream from site: %s\n", err)
	}
  
	fmt.Printf("Success - Upstream DNS request for xaxis.com returned: %s\n", conn.RemoteAddr().String())

	conn.Close()
  ```


