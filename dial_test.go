package dns

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"testing"

	"github.com/benburkert/dns/internal/must"
)

func TestDialer(t *testing.T) {
	t.Parallel()

	t.Run("bad-network", func(t *testing.T) {
		t.Parallel()

		conn, _ := net.Pipe()

		dialer := &Dialer{
			DialContext: func(context.Context, string, string) (net.Conn, error) {
				return conn, nil
			},
		}

		_, err := dialer.DialAddr(context.Background(), conn.RemoteAddr())
		if want, got := ErrUnsupportedNetwork, err; want != got {
			t.Errorf("want err = %q, got %q", want, got)
		}
	})

	t.Run("tcp-network", func(t *testing.T) {
		t.Parallel()

		ln, err := net.Listen("tcp", ":0")
		if err != nil {
			t.Fatal(err)
		}

		conn, err := new(Dialer).DialAddr(context.Background(), ln.Addr())
		if err != nil {
			t.Fatal(err)
		}

		if _, ok := conn.(*StreamConn); !ok {
			t.Errorf("want tcp dial to create StreamConn, got %+v", conn)
		}
	})

	t.Run("udp-network", func(t *testing.T) {
		t.Parallel()

		ln, err := net.ListenPacket("udp", ":0")
		if err != nil {
			t.Fatal(err)
		}

		conn, err := new(Dialer).DialAddr(context.Background(), ln.LocalAddr())
		if err != nil {
			t.Fatal(err)
		}

		if _, ok := conn.(*PacketConn); !ok {
			t.Errorf("want tcp dial to create PacketConn, got %+v", conn)
		}
	})

	t.Run("tcp-tls-network", func(t *testing.T) {
		t.Parallel()

		ca := must.CACert("ca.dev", nil)

		srvConfig := &tls.Config{
			Certificates: []tls.Certificate{
				*must.LeafCert("dns-server.dev", ca).TLS(),
				*ca.TLS(),
			},
		}

		ln, err := tls.Listen("tcp", ":0", srvConfig)
		if err != nil {
			t.Fatal(err)
		}

		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					log.Printf(err.Error())
					return
				}

				if err := conn.(*tls.Conn).Handshake(); err != nil {
					log.Printf(err.Error())
					return
				}

				if err := conn.Close(); err != nil {
					log.Printf(err.Error())
					return
				}
			}
		}()

		dialer := &Dialer{
			TLSConfig: &tls.Config{
				ServerName: "dns-server.dev",
				RootCAs:    must.CertPool(ca.TLS()),
			},
		}

		addr := OverTLSAddr{ln.Addr()}
		conn, err := dialer.DialAddr(context.Background(), addr)
		if err != nil {
			t.Fatal(err)
		}

		if _, ok := conn.(*StreamConn); !ok {
			t.Errorf("want tcp dial to create StreamConn, got %+v", conn)
		}
	})
}
