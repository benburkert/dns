package dns

import (
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/benburkert/dns/internal/must"
)

var transportTests = []struct {
	name string

	req *Message

	res *Message
}{
	{
		name: "single-A-match",

		req: &Message{
			Questions: []Question{questions["A"]},
		},

		res: &Message{
			Response:  true,
			Questions: []Question{questions["A"]},
			Answers:   []Resource{answers[questions["A"]]},
		},
	},
	{
		name: "single-AAAA-match",

		req: &Message{
			Questions: []Question{questions["AAAA"]},
		},

		res: &Message{
			Response:  true,
			Questions: []Question{questions["AAAA"]},
			Answers:   []Resource{answers[questions["AAAA"]]},
		},
	},
}

func TestTransport(t *testing.T) {
	t.Parallel()

	srv := &testServer{
		Answers: answers,
	}

	t.Run("udp", func(t *testing.T) {
		t.Parallel()

		conn, err := net.ListenPacket("udp", ":0")
		if err != nil {
			t.Fatal(err)
		}

		if err := srv.StartUDP(conn); err != nil {
			t.Fatal(err)
		}

		testTransport(t, new(Transport), conn.LocalAddr())
	})

	t.Run("tcp", func(t *testing.T) {
		t.Parallel()

		ln, err := net.Listen("tcp", ":0")
		if err != nil {
			t.Fatal(err)
		}

		if err := srv.StartTCP(ln); err != nil {
			t.Fatal(err)
		}

		testTransport(t, new(Transport), ln.Addr())
	})

	t.Run("tcp-tls", func(t *testing.T) {
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

		if err := srv.StartTCP(ln); err != nil {
			t.Fatal(err)
		}

		tport := &Transport{
			TLSConfig: &tls.Config{
				ServerName: "dns-server.dev",
				RootCAs:    must.CertPool(ca.TLS()),
			},
		}

		testTransport(t, tport, OverTLSAddr{ln.Addr()})
	})
}

func TestTransportProxy(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}

	tport := &Transport{
		Proxy: func(_ context.Context, _ net.Addr) (net.Addr, error) {
			return ln.Addr(), nil
		},
	}

	conn, err := tport.DialAddr(context.Background(), new(net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}

	if want, got := ln.Addr().(*net.TCPAddr).Port, conn.RemoteAddr().(*net.TCPAddr).Port; want != got {
		t.Errorf("want dialed addr %q, got %q", want, got)
	}
}

func testTransport(t *testing.T, tport *Transport, addr net.Addr) {
	for _, test := range transportTests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			conn, err := tport.DialAddr(context.Background(), addr)
			if err != nil {
				t.Fatal(err)
			}

			if err := conn.Send(test.req); err != nil {
				t.Fatal(err)
			}

			var msg Message
			if err := conn.Recv(&msg); err != nil {
				t.Fatal(err)
			}

			if want, got := test.res, &msg; !reflect.DeepEqual(want, got) {
				t.Errorf("want response %+v, got %+v", want, got)
			}
		})
	}
}

var (
	questions = map[string]Question{
		"A": Question{
			Name:  "A.dev.",
			Type:  TypeA,
			Class: ClassINET,
		},
		"AAAA": Question{
			Name:  "AAAA.dev.",
			Type:  TypeAAAA,
			Class: ClassINET,
		},
	}

	answers = map[Question]Resource{
		questions["A"]: Resource{
			Name:  "A.dev.",
			Class: ClassINET,
			TTL:   60 * time.Second,
			Record: &A{
				A: net.IPv4(127, 0, 0, 1).To4(),
			},
		},
		questions["AAAA"]: Resource{
			Name:  "AAAA.dev.",
			Class: ClassINET,
			TTL:   60 * time.Second,
			Record: &AAAA{
				AAAA: net.ParseIP("::1"),
			},
		},
	}
)

type testServer struct {
	Answers map[Question]Resource
}

func (s *testServer) StartTCP(ln net.Listener) error {
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Print(err.Error())
				return
			}

			sconn := &StreamConn{Conn: conn}
			go func() {
				for {
					var msg Message
					if err := sconn.Recv(&msg); err != nil {
						if err != io.EOF {
							log.Print(err.Error())
						}
						return
					}

					if err := sconn.Send(s.handle(&msg)); err != nil {
						panic(err)
						log.Print(err.Error())
						return
					}
				}
			}()
		}
	}()

	return nil
}

func (s *testServer) StartUDP(conn net.PacketConn) error {
	go func() {
		defer conn.Close()

		buf := make([]byte, 512)
		for {
			n, addr, err := conn.ReadFrom(buf[:512])
			if err != nil {
				log.Print(err.Error())
				return
			}

			msg := new(Message)
			if _, err := msg.Unpack(buf[:n]); err != nil {
				log.Print(err.Error())
				return
			}

			buf, err := s.handle(msg).Pack(buf[:0], true)
			if err != nil {
				log.Print(err.Error())
				return
			}

			if _, err := conn.WriteTo(buf, addr); err != nil {
				log.Print(err.Error())
				return
			}
		}
	}()

	return nil
}

func (s *testServer) handle(req *Message) *Message {
	res := &Message{
		ID:        req.ID,
		Response:  true,
		Questions: req.Questions,
	}

	for _, q := range req.Questions {
		if answer, ok := s.Answers[q]; ok {
			res.Answers = append(res.Answers, answer)
		}
	}

	return res
}
