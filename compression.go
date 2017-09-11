package dns

import (
	"strings"
)

// Compressor encodes domain names.
type Compressor interface {
	Length(...string) int
	Pack([]byte, string) ([]byte, error)
}

// Decompressor decodes domain names.
type Decompressor interface {
	Unpack([]byte) (string, []byte, error)
}

type compressor map[string]int

func (c compressor) Length(names ...string) int {
	var visited map[string]struct{}
	if c != nil {
		visited = make(map[string]struct{})
	}

	var n int
	for _, name := range names {
		n += c.length(name, visited)
	}
	return n
}

func (c compressor) length(name string, visited map[string]struct{}) int {
	if name == "." || name == "" {
		return 1
	}

	if c != nil {
		if _, ok := c[name]; ok {
			return 2
		}
		if _, ok := visited[name]; ok {
			return 2
		}

		visited[name] = struct{}{}
	}

	pvt := strings.IndexByte(name, '.')
	return pvt + 1 + c.length(name[pvt+1:], visited)
}

func (c compressor) Pack(b []byte, fqdn string) ([]byte, error) {
	if fqdn == "." || fqdn == "" {
		return append(b, 0x00), nil
	}

	if c != nil {
		if idx, ok := c[fqdn]; ok {
			ptr, err := pointerTo(idx)
			if err != nil {
				return nil, err
			}

			return append(b, ptr...), nil
		}
	}

	pvt := strings.IndexByte(fqdn, '.')
	if pvt == 0 {
		return nil, errZeroSegLen
	}
	if pvt > 63 {
		return nil, errSegTooLong
	}

	if c != nil {
		idx := len(b)
		if int(uint16(idx)) != idx {
			return nil, errInvalidPtr
		}
		c[fqdn] = idx
	}

	b = append(b, byte(pvt))
	b = append(b, fqdn[:pvt]...)

	return c.Pack(b, fqdn[pvt+1:])
}

type decompressor []byte

func (d decompressor) Unpack(b []byte) (string, []byte, error) {
	return d.unpack(b, nil)
}

func (d decompressor) unpack(b []byte, visited []int) (string, []byte, error) {
	lenb := len(b)
	if lenb == 0 {
		return "", nil, errBaseLen
	}
	if b[0] == 0x00 {
		return ".", b[1:], nil
	}
	if lenb < 2 {
		return "", nil, errBaseLen
	}

	if isPointer(b[0]) {
		if d == nil {
			return "", nil, errInvalidPtr
		}

		ptr := nbo.Uint16(b[:2])
		name, err := d.deref(ptr, visited)
		if err != nil {
			return "", nil, err
		}

		return name, b[2:], nil
	}

	lenl, b := int(b[0]), b[1:]

	if len(b) < lenl {
		return "", nil, errCalcLen
	}

	label := string(b[:lenl])

	suffix, b, err := d.unpack(b[lenl:], visited)
	if err != nil {
		return "", nil, err
	}
	if suffix == "." {
		return label + ".", b, nil
	}
	return label + "." + suffix, b, nil
}

func (d decompressor) deref(ptr uint16, visited []int) (string, error) {
	idx := int(ptr & 0x3FFF)
	if len(d) < idx {
		return "", errInvalidPtr
	}

	if isPointer(d[idx]) {
		return "", errInvalidPtr
	}

	for _, v := range visited {
		if idx == v {
			return "", errPtrCycle
		}
	}

	name, _, err := d.unpack(d[idx:], append(visited, idx))
	return name, err
}

func isPointer(b byte) bool { return b&0xC0 > 0 }

func pointerTo(idx int) ([]byte, error) {
	ptr := uint16(idx)
	if int(ptr) != idx {
		return nil, errInvalidPtr
	}
	ptr |= 0xC000

	buf := [2]byte{}
	nbo.PutUint16(buf[:], ptr)
	return buf[:], nil
}
