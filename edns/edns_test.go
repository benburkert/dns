package edns

import (
	"bytes"
	"reflect"
	"testing"
)

func TestOptionPackUnpack(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string

		opt Option

		raw []byte
	}{
		{
			name: "COOKIE: client cookie to unknown server",

			opt: Option{
				Code: OptionCodeCookie,
				Data: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
			},

			raw: []byte{
				0x00, 0x0A, // OPTION-CODE = 10
				0x00, 0x08, // OPTION-LENGTH = 8
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // Client Cookie (fixed size, 8 bytes)
			},
		},
		{
			name: "COOKIE: client cookie to known server",

			opt: Option{
				Code: OptionCodeCookie,
				Data: []byte{
					0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,

					0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
					0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
				},
			},

			raw: []byte{
				0x00, 0x0A, // OPTION-CODE = 10
				0x00, 0x18, // OPTION-LENGTH = 24

				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // Client Cookie (fixed size, 8 bytes)

				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, // Server Cookie  (variable size, 8 to 32 bytes)
				0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
			},
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			raw, err := test.opt.Pack(nil)
			if err != nil {
				t.Fatal(err)
			}

			if want, got := test.raw, raw; !bytes.Equal(want, got) {
				t.Errorf("want raw option %+v, got %+v", want, got)
			}

			opt := new(Option)
			buf, err := opt.Unpack(raw)
			if err != nil {
				t.Fatal(err)
			}
			if len(buf) > 0 {
				t.Errorf("left-over data after unpack: %x", buf)
			}

			if want, got := test.opt, *opt; !reflect.DeepEqual(want, got) {
				t.Errorf("want option %+v, got %+v", want, got)
			}
		})
	}
}
