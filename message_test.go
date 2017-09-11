package dns

import (
	"bytes"
	"fmt"
	"net"
	"reflect"
	"testing"
	"time"
)

func TestQuestionPackUnpack(t *testing.T) {
	t.Parallel()

	tests := []struct {
		question Question
		raw      []byte
	}{
		{
			question: Question{
				Name:  ".",
				Type:  TypeA,
				Class: ClassINET,
			},

			raw: []byte{0x0, 0x0, 0x1, 0x0, 0x1},
		},
		{
			question: Question{
				Name:  "google.com.",
				Type:  TypeAAAA,
				Class: ClassINET,
			},

			raw: []byte{
				0x6, 'g', 'o', 'o', 'g', 'l', 'e',
				0x3, 'c', 'o', 'm',
				0x0,
				0x0, 0x1C, 0x0, 0x1,
			},
		},
	}

	for _, test := range tests {
		test := test

		t.Run(string(test.question.Name), func(t *testing.T) {
			t.Parallel()

			raw, err := test.question.Pack(nil, nil)
			if err != nil {
				t.Fatal(err)
			}

			if want, got := test.raw, raw; !bytes.Equal(want, got) {
				t.Errorf("want raw question %x, got %x", want, got)
			}

			q := new(Question)
			buf, err := q.Unpack(raw, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(buf) > 0 {
				t.Errorf("left-over data after unpack: %x", buf)
			}

			if want, got := test.question, *q; want != got {
				t.Errorf("want question %+v, got %+v", want, got)
			}
		})
	}
}

func TestNamePackUnpack(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  []byte
		err  error
	}{
		{".", []byte{0x0}, nil},
		{"google..com", nil, errZeroSegLen},
		{"google.com.", rawGoogleCom, nil},
		{".google.com.", nil, errZeroSegLen},
		{"www..google.com.", nil, errZeroSegLen},
		{"www.google.com.", append([]byte{0x3, 'w', 'w', 'w'}, rawGoogleCom...), nil},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			raw, err := compressor(nil).Pack(nil, test.name)
			if err != nil {
				if want, got := test.err, err; want != got {
					t.Errorf("want err %q, got %q", want, got)
				}
				return
			}

			if want, got := test.raw, raw; !bytes.Equal(want, got) {
				t.Fatal("want raw name %x, got %x", want, got)
			}

			name, buf, err := decompressor(nil).Unpack(raw)
			if err != nil {
				if want, got := test.err, err; want != got {
					t.Fatalf("want err %q, got %q", want, got)
				}
				return
			}
			if len(buf) > 0 {
				t.Errorf("left-over data after unpack: %x", buf)
			}

			if want, got := test.name, name; want != got {
				t.Errorf("want unpacked name %q, got %q", want, got)
			}
		})
	}
}

func TestMessagePackUnpack(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string

		msg      Message
		compress bool

		raw []byte
	}{
		{
			name: ".	IN	AAAA",

			msg: Message{
				ID:               0x1001,
				RecursionDesired: true,
				Questions: []Question{
					{
						Name:  ".",
						Type:  TypeAAAA,
						Class: ClassINET,
					},
				},
			},

			raw: []byte{
				0x10, 0x01, // ID=0x1001
				0x01, 0x00, // RD=1
				0x00, 0x01, // QDCOUNT=1
				0x00, 0x00, // ANCOUNT=0
				0x00, 0x00, // NSCOUNT=0
				0x00, 0x00, // ARCOUNT=0

				0x00, 0x00, 0x1C, 0x00, 0x01, // .	IN	AAAA
			},
		},
		{
			name: "txt.example.com.	IN	TXT",

			msg: Message{
				ID:       0x01,
				Response: true,
				Questions: []Question{
					{
						Name:  "txt.example.com.",
						Type:  TypeTXT,
						Class: ClassINET,
					},
				},
				Answers: []Resource{
					{
						Name:   "txt.example.com.",
						Class:  ClassINET,
						TTL:    60 * time.Second,
						Record: &TXT{"abcd"},
					},
				},
			},

			raw: []byte{
				0x00, 0x01, // ID=0x0001
				0x80, 0x00, // QR=1
				0x00, 0x01, // QDCOUNT=1
				0x00, 0x01, // ANCOUNT=1
				0x00, 0x00, // NSCOUNT=0
				0x00, 0x00, // ARCOUNT=0

				// txt.example.com.	IN	TXT
				0x03, 't', 'x', 't',
				0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
				0x03, 'c', 'o', 'm',
				0x00,
				0x00, 0x10, 0x00, 0x01, // TYPE=TXT,CLASS=IN

				// txt.example.com.	60	IN	TXT	"abcd"
				0x03, 't', 'x', 't',
				0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
				0x03, 'c', 'o', 'm',
				0x00,
				0x00, 0x10, 0x00, 0x01, // TYPE=TXT,CLASS=IN
				0x00, 0x00, 0x00, 0x3C, // TTL=60
				0x00, 0x05, // RDLENGTH=5

				0x04, 'a', 'b', 'c', 'd',
			},
		},
		{
			name: "compressed response",

			msg: Message{
				Response: true,
				Answers: []Resource{
					{
						Name:  "example.com.",
						Class: ClassINET,
						TTL:   60 * time.Second,
						Record: &A{
							A: net.IPv4(127, 0, 0, 1).To4(),
						},
					},
				},
				Questions: []Question{
					{
						Name:  "example.com.",
						Type:  TypeA,
						Class: ClassINET,
					},
				},
			},
			compress: true,

			raw: []byte{
				0x00, 0x00, // ID=0x0001
				0x80, 0x00, // QR=1
				0x00, 0x01, // QDCOUNT=1
				0x00, 0x01, // ANCOUNT=1
				0x00, 0x00, // NSCOUNT=0
				0x00, 0x00, // ARCOUNT=0

				// example.com.	IN	A
				0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
				0x03, 'c', 'o', 'm',
				0x00,
				0x00, 0x01, 0x00, 0x01, // TYPE=A,CLASS=IN

				// example.com	60	IN A 127.0.0.1
				0xC0, 0x0C,
				0x00, 0x01, 0x00, 0x01, // TYPE=TXT,CLASS=IN
				0x00, 0x00, 0x00, 0x3C, // TTL=60
				0x00, 0x04, // RDLENGTH=5

				0x7F, 0x00, 0x00, 0x01, // 127.0.0.1
			},
		},
	}

	for _, test := range tests {
		test := test

		t.Run(string(test.name), func(t *testing.T) {
			t.Parallel()

			raw, err := test.msg.Pack(nil, test.compress)
			if err != nil {
				t.Fatal(err)
			}

			if want, got := test.raw, raw; !bytes.Equal(want, got) {
				t.Errorf("want raw message %+v, got %+v", want, got)
			}

			msg := new(Message)
			buf, err := msg.Unpack(raw)
			if err != nil {
				t.Fatal(err)
			}
			if len(buf) > 0 {
				t.Errorf("left-over data after unpack: %x", buf)
			}

			if want, got := test.msg, *msg; !reflect.DeepEqual(want, got) {
				t.Errorf("want message %+v, got %+v", want, got)
			}
		})
	}
}

func TestMessageCompress(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		msg  Message
		raw  []byte
	}{
		{
			name: "multi-A-question",

			msg: Message{
				Questions: []Question{
					{
						Name:  "aaa.",
						Type:  TypeA,
						Class: ClassINET,
					},
					{
						Name:  "bbb.aaa.",
						Type:  TypeA,
						Class: ClassINET,
					},
					{
						Name:  "ccc.bbb.aaa.",
						Type:  TypeA,
						Class: ClassINET,
					},
				},
			},

			raw: []byte{
				0x00, 0x00, // ID=0x0000
				0x00, 0x00, // QR=0
				0x00, 0x03, // QDCOUNT=0
				0x00, 0x00, // ANCOUNT=0
				0x00, 0x00, // NSCOUNT=0
				0x00, 0x00, // ARCOUNT=0

				// aaa.	IN	A
				0x03, 'a', 'a', 'a',
				0x00,
				0x00, 0x01, 0x00, 0x01,

				// bbb.aaa.	IN	A
				0x03, 'b', 'b', 'b',
				0xC0, 0x0C,
				0x00, 0x01, 0x00, 0x01,

				// ccc.bbb.aaa.	IN	A
				0x03, 'c', 'c', 'c',
				0xC0, 0x15,
				0x00, 0x01, 0x00, 0x01,
			},
		},
	}

	for _, test := range tests {
		test := test

		t.Run(string(test.name), func(t *testing.T) {
			t.Parallel()

			raw, err := test.msg.Pack(nil, true)
			if err != nil {
				t.Fatal(err)
			}

			if want, got := test.raw, raw; !bytes.Equal(want, got) {
				t.Errorf("want raw message %+v, got %+v", want, got)
			}

			msg := new(Message)
			buf, err := msg.Unpack(raw)
			if err != nil {
				t.Fatal(err)
			}
			if len(buf) > 0 {
				t.Errorf("left-over data after unpack: %x", buf)
			}

			if want, got := test.msg, *msg; !reflect.DeepEqual(want, got) {
				t.Errorf("want message %+v, got %+v", want, got)
			}
		})
	}
}

var (
	rawGoogleCom = []byte{
		0x6, 'g', 'o', 'o', 'g', 'l', 'e',
		0x3, 'c', 'o', 'm',
		0x0,
	}
)

func BenchmarkMessagePack(b *testing.B) {
	b.Run("small-message", func(b *testing.B) {
		msg := smallTestMsg()

		for _, bufsize := range []int{0, 512} {
			bufsize := bufsize

			b.Run(fmt.Sprintf("buf=%d", bufsize), func(b *testing.B) {
				benchamarkMessagePack(b, msg, make([]byte, bufsize))
			})
		}
	})

	b.Run("large-message", func(b *testing.B) {
		msg := largeTestMsg()

		for _, bufsize := range []int{0, 512, 4096} {
			bufsize := bufsize

			b.Run(fmt.Sprintf("buf=%d", bufsize), func(b *testing.B) {
				benchamarkMessagePack(b, msg, make([]byte, bufsize))
			})
		}
	})
}

func benchamarkMessagePack(b *testing.B, msg Message, buf []byte) {
	tmp, err := msg.Pack(nil, false)
	if err != nil {
		b.Fatal(err)
	}

	b.SetBytes(int64(len(tmp)))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, err := msg.Pack(buf[:0], false); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMessageCompress(b *testing.B) {
	b.Run("small-message", func(b *testing.B) {
		msg := smallTestMsg()

		for _, bufsize := range []int{0, 512} {
			bufsize := bufsize

			b.Run(fmt.Sprintf("buf=%d", bufsize), func(b *testing.B) {
				benchamarkMessageCompress(b, msg, make([]byte, bufsize))
			})
		}
	})

	b.Run("large-message", func(b *testing.B) {
		msg := largeTestMsg()

		for _, bufsize := range []int{0, 512, 4096} {
			bufsize := bufsize

			b.Run(fmt.Sprintf("buf=%d", bufsize), func(b *testing.B) {
				benchamarkMessageCompress(b, msg, make([]byte, bufsize))
			})
		}
	})
}

func benchamarkMessageCompress(b *testing.B, msg Message, buf []byte) {
	tmp, err := msg.Pack(nil, false)
	if err != nil {
		b.Fatal(err)
	}

	b.SetBytes(int64(len(tmp)))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, err := msg.Pack(buf[:0], true); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMessageUnpack(b *testing.B) {
	b.Run("small-message", func(b *testing.B) {
		benchamarkMessageUnpack(b, smallTestMsg(), false)
	})

	b.Run("large-message", func(b *testing.B) {
		benchamarkMessageUnpack(b, largeTestMsg(), false)
	})
}

func BenchmarkMessageDecompress(b *testing.B) {
	b.Run("small-message", func(b *testing.B) {
		benchamarkMessageUnpack(b, smallTestMsg(), true)
	})

	b.Run("large-message", func(b *testing.B) {
		benchamarkMessageUnpack(b, largeTestMsg(), true)
	})
}

func benchamarkMessageUnpack(b *testing.B, msg Message, compress bool) {
	buf, err := msg.Pack(nil, compress)
	if err != nil {
		b.Fatal(err)
	}

	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		var msg Message
		if _, err := msg.Unpack(buf); err != nil {
			b.Fatal(err)
		}
	}
}

func smallTestMsg() Message {
	name := "example.com."

	return Message{
		Response:      true,
		Authoritative: true,

		Questions: []Question{
			{
				Name:  name,
				Type:  TypeA,
				Class: ClassINET,
			},
		},
		Answers: []Resource{
			{
				Name:  name,
				Class: ClassINET,
				Record: &A{
					A: net.IPv4(127, 0, 0, 1).To4(),
				},
			},
		},
		Authorities: []Resource{
			{
				Name:  name,
				Class: ClassINET,
				Record: &A{
					A: net.IPv4(127, 0, 0, 1).To4(),
				},
			},
		},
		Additionals: []Resource{
			{
				Name:  name,
				Class: ClassINET,
				Record: &A{
					A: net.IPv4(127, 0, 0, 1).To4(),
				},
			},
		},
	}
}

func largeTestMsg() Message {
	name := "foo.bar.example.com."

	return Message{
		Response:      true,
		Authoritative: true,
		Questions: []Question{
			{
				Name:  name,
				Type:  TypeA,
				Class: ClassINET,
			},
		},
		Answers: []Resource{
			{
				Name:  name,
				Class: ClassINET,
				Record: &A{
					A: net.IPv4(127, 0, 0, 1),
				},
			},
			{
				Name:  name,
				Class: ClassINET,
				Record: &A{
					A: net.IPv4(127, 0, 0, 2),
				},
			},
			{
				Name:  name,
				Class: ClassINET,
				Record: &AAAA{
					AAAA: net.ParseIP("::1"),
				},
			},
			{
				Name:  name,
				Class: ClassINET,
				Record: &CNAME{
					CNAME: "alias.example.com.",
				},
			},
			{
				Name:  name,
				Class: ClassINET,
				Record: &SOA{
					NS:      "ns1.example.com.",
					MBox:    "mb.example.com.",
					Serial:  1,
					Refresh: 2 * time.Second,
					Retry:   3 * time.Second,
					Expire:  4 * time.Second,
					MinTTL:  5 * time.Second,
				},
			},
			{
				Name:  name,
				Class: ClassINET,
				Record: &PTR{
					PTR: "ptr.example.com.",
				},
			},
			{
				Name:  name,
				Class: ClassINET,
				Record: &MX{
					Pref: 7,
					MX:   "mx.example.com.",
				},
			},
			{
				Name:  name,
				Class: ClassINET,
				Record: &SRV{
					Priority: 8,
					Weight:   9,
					Port:     11,
					Target:   "srv.example.com.",
				},
			},
		},
		Authorities: []Resource{
			{
				Name:  name,
				Class: ClassINET,
				Record: &NS{
					NS: "ns1.example.com.",
				},
			},
			{
				Name:  name,
				Class: ClassINET,
				Record: &NS{
					NS: "ns2.example.com.",
				},
			},
		},
		Additionals: []Resource{
			{
				Name:  name,
				Class: ClassINET,
				Record: &TXT{
					TXT: "So Long, and Thanks for All the Fish",
				},
			},
			{
				Name:  name,
				Class: ClassINET,
				Record: &TXT{
					TXT: "Hamster Huey and the Gooey Kablooie",
				},
			},
		},
	}
}
