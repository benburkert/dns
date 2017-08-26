package dns

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"reflect"
	"testing"
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
			Header:    Header{Response: true},
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
			Header:    Header{Response: true},
			Questions: []Question{questions["AAAA"]},
			Answers:   []Resource{answers[questions["AAAA"]]},
		},
	},
}

func TestTransport(t *testing.T) {
	t.Parallel()

	tport := new(Transport)

	t.Run("tcp", func(t *testing.T) {
		t.Parallel()

		testTransport(t, tport, new(net.TCPAddr))
	})

	t.Run("udp", func(t *testing.T) {
		t.Parallel()

		testTransport(t, tport, new(net.UDPAddr))
	})
}

func testTransport(t *testing.T, tport *Transport, addr net.Addr) {
	srv := &testServer{
		Addr:    addr,
		Answers: answers,
	}

	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}

	for _, test := range transportTests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			query := &Query{
				Message:    test.req,
				RemoteAddr: srv.Addr,
			}

			msg, err := tport.RoundTrip(context.Background(), query)
			if err != nil {
				t.Fatal(err)
			}

			if want, got := test.res, msg; !reflect.DeepEqual(want, got) {
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
		questions["A"]: &AResource{
			ResourceHeader: ResourceHeader{
				Name:  "A.dev.",
				Type:  TypeA,
				Class: ClassINET,
				TTL:   60,
			},
			A: [4]byte{127, 0, 0, 1},
		},
		questions["AAAA"]: &AAAAResource{
			ResourceHeader: ResourceHeader{
				Name:  "A.dev.",
				Type:  TypeAAAA,
				Class: ClassINET,
				TTL:   60,
			},
			AAAA: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		},
	}
)

type testServer struct {
	Addr net.Addr

	Answers map[Question]Resource
}

func (s *testServer) startUDP() error {
	conn, err := net.ListenPacket(s.Addr.Network(), s.Addr.String())
	if err != nil {
		return err
	}
	s.Addr = conn.LocalAddr()

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
			if err := msg.Unpack(buf[:n]); err != nil {
				log.Print(err.Error())
				return
			}

			buf, err := s.handle(msg).AppendPack(buf[:0])
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
func (s *testServer) Start() error {
	switch s.Addr.(type) {
	case *net.TCPAddr:
		return s.startTCP()
	case *net.UDPAddr:
		return s.startUDP()
	default:
		return errors.New("unknown network")
	}
}

func (s *testServer) startTCP() error {
	ln, err := net.Listen(s.Addr.Network(), s.Addr.String())
	if err != nil {
		return err
	}
	s.Addr = ln.Addr()

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
						log.Print(err.Error())
						return
					}
				}
			}()
		}
	}()

	return nil
}

func (s *testServer) handle(req *Message) *Message {
	res := &Message{
		Header: Header{
			ID:       req.ID,
			Response: true,
		},
		Questions: req.Questions,
	}

	for _, q := range req.Questions {
		if answer, ok := s.Answers[q]; ok {
			res.Answers = append(res.Answers, answer)
		}
	}

	return res
}
