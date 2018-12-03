package dns

import (
	"context"
	cryptorand "crypto/rand"
	"io"
	"math/big"
	"net"
	"sync/atomic"
	//"fmt"
	//"runtime/debug"
)

// NameServers is a slice of DNS nameserver addresses.
type NameServers []net.Addr

// RLS 2/15/2018 - This is a custom key used in context structs to tell the dialer to use an alternate DNS server if available.
type key string
const UpstreamKey key = "upstream"


// Random picks a random Addr from s every time.
func (s NameServers) Random(rand io.Reader) ProxyFunc {
	max := big.NewInt(int64(len(s)))
	return func(_ context.Context, _ net.Addr) (net.Addr, error) {
		idx, err := cryptorand.Int(rand, max)
		if err != nil {
			return nil, err
		}

		return s[idx.Uint64()], nil
	}
}

// RoundRobin picks the next Addr of s by index of the last pick.
func (s NameServers) RoundRobin() ProxyFunc {
	var idx uint32
	return func(_ context.Context, _ net.Addr) (net.Addr, error) {
		return s[int(atomic.AddUint32(&idx, 1)-1)%len(s)], nil
	}
}

// Alternate returns the first DNS server by default. If the UpstreamKey
// is found in the context object, it will randomly select one of the alternate
// DNS servers, if any were provided. Typical usage is to set the first address
// to 127.0.0.1 and the others to upstream DNS servers.
func (s NameServers) Upstream(rand io.Reader) ProxyFunc {

	max := big.NewInt(int64(len(s) - 1))
	return func(ctx context.Context, _ net.Addr) (net.Addr, error) {
		//fmt.Println("[DEBUG] DNS/Upstream()")
		// ctx.Value returns nil if ctx has no value for the key
		useUpstream := ctx.Value(UpstreamKey)

		// No upstream key was provided, so use the first entry
		if useUpstream == nil || len(s) == 1 {
			//fmt.Println("[DEBUG] DNS/Upstream() - No upstream key. Using first entry.", ctx)
			//debug.PrintStack()
			return s[0], nil
		}

		// Select a random number between 0 and max index - 1
		idx, err := cryptorand.Int(rand, max)
		if err != nil {
			return nil, err
		}

		//fmt.Printf("[DEBUG] DNS.Upstream() - FOUND KEY %d %s\n", idx.Uint64() + 1, s[idx.Uint64() + 1].String())
		return s[idx.Uint64() + 1], nil
	}
}

// RLS 8/10/2018 - Returns first entry
func (s NameServers) First() ProxyFunc {
	return func(ctx context.Context, _ net.Addr) (net.Addr, error) {
		return s[0], nil
	}
}
