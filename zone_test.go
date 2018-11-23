package dns

import (
	"context"
	"net"
	"reflect"
	"testing"
	"time"
)

var localhostZone = &Zone{
	Origin: "localhost.",
	TTL:    24 * time.Hour,
	SOA: &SOA{
		NS:   "dns.localhost.",
		MBox: "hostmaster.localhost.",
	},
	RRs: RRSet{
		"1.app": {
			TypeA: {
				&A{net.IPv4(10, 42, 0, 1).To4()},
			},
			TypeAAAA: {
				&AAAA{net.ParseIP("dead:beef::1")},
			},
		},
		"2.app": {
			TypeA: {
				&A{net.IPv4(10, 42, 0, 2).To4()},
			},
			TypeAAAA: {
				&AAAA{net.ParseIP("dead:beef::2")},
			},
		},
		"3.app": {
			TypeA: {
				&A{net.IPv4(10, 42, 0, 3).To4()},
			},
			TypeAAAA: {
				&AAAA{net.ParseIP("dead:beef::3")},
			},
		},
		"app": {
			TypeA: {
				&A{net.IPv4(10, 42, 0, 1).To4()},
				&A{net.IPv4(10, 42, 0, 2).To4()},
				&A{net.IPv4(10, 42, 0, 3).To4()},
			},
			TypeAAAA: {
				&AAAA{net.ParseIP("dead:beef::1")},
				&AAAA{net.ParseIP("dead:beef::2")},
				&AAAA{net.ParseIP("dead:beef::3")},
			},
		},
		"cname": {
			TypeA: {
				&CNAME{CNAME: "app.localhost."},
			},
		},
	},
}

func TestZone(t *testing.T) {
	t.Parallel()

	srv := mustServer(localhostZone)

	addr, err := net.ResolveUDPAddr("udp", srv.Addr)
	if err != nil {
		t.Fatal(err)
	}

	client := new(Client)

	q := &Query{
		RemoteAddr: addr,
		Message: &Message{
			Questions: []Question{
				{
					Name:  "app.localhost.",
					Type:  TypeA,
					Class: ClassIN,
				},
			},
		},
	}

	res, err := client.Do(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}

	if want, got := 3, len(res.Answers); want != got {
		t.Errorf("want %d answers, got %d", want, got)
	}

	for i, answer := range res.Answers {
		rec := localhostZone.RRs["app"][TypeA][i]
		if want, got := rec.(*A), answer.Record.(*A); !reflect.DeepEqual(*want, *got) {
			t.Errorf("want answer record %+v, got %+v", *want, *got)
		}
	}

	q.Message = &Message{
		Questions: []Question{
			{
				Name:  "unknown.",
				Type:  TypeA,
				Class: ClassIN,
			},
		},
	}

	if res, err = client.Do(context.Background(), q); err != nil {
		t.Fatal(err)
	}

	if want, got := 0, len(res.Answers); want != got {
		t.Errorf("want %d answers, got %d", want, got)
	}
	if want, got := 1, len(res.Authorities); want != got {
		t.Errorf("want %d authorities, got %d", want, got)
	}

	soa, ok := res.Authorities[0].Record.(*SOA)
	if !ok {
		t.Fatalf("non SOA authority record: %+v", res.Authorities[0])
	}
	if want, got := localhostZone.SOA, soa; !reflect.DeepEqual(*want, *got) {
		t.Errorf("want SOA record %+v, got %+v", *want, *got)
	}

	// test SOA query

	q.Message = &Message{
		Questions: []Question{
			{
				Name:  "localhost.",
				Type:  TypeSOA,
				Class: ClassIN,
			},
		},
	}

	if res, err = client.Do(context.Background(), q); err != nil {
		t.Fatal(err)
	}
	if want, got := 1, len(res.Answers); want != got {
		t.Errorf("want %d answers, got %d", want, got)
	}
	if want, got := 0, len(res.Authorities); want != got {
		t.Errorf("want %d authorities, got %d", want, got)
	}

	if soa, ok = res.Answers[0].Record.(*SOA); !ok {
		t.Fatalf("non SOA authority record: %+v", res.Authorities[0])
	}
	if want, got := localhostZone.SOA, soa; !reflect.DeepEqual(*want, *got) {
		t.Errorf("want SOA record %+v, got %+v", *want, *got)
	}

	// test recursive query + cname

	q.Message = &Message{
		RecursionDesired: true,
		Questions: []Question{
			{
				Name:  "cname.localhost.",
				Type:  TypeA,
				Class: ClassIN,
			},
		},
	}

	if res, err = client.Do(context.Background(), q); err != nil {
		t.Fatal(err)
	}

	if want, got := 4, len(res.Answers); want != got {
		t.Errorf("want %d answers, got %d", want, got)
	}
	if want, got := localhostZone.RRs["cname"][TypeA][0].(*CNAME), res.Answers[0].Record.(*CNAME); !reflect.DeepEqual(*want, *got) {
		t.Fatalf("want %+v record, got %+v", want, got)
	}
	for i, answer := range res.Answers[1:] {
		rec := localhostZone.RRs["app"][TypeA][i]
		if want, got := rec.(*A), answer.Record.(*A); !reflect.DeepEqual(*want, *got) {
			t.Errorf("want answer record %+v, got %+v", *want, *got)
		}
	}
}
