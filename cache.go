package dns

import (
	"context"
	"sync"
	"time"
)

// Cache is a DNS query cache handler.
type Cache struct {
	mu    sync.RWMutex
	cache map[Question]*Message
}

// ServeDNS answers query questions from a local cache, and forwards unanswered
// questions upstream, then caches the answers from the response.
func (c *Cache) ServeDNS(ctx context.Context, w MessageWriter, r *Query) {
	var (
		miss bool

		now = time.Now()
	)

	c.mu.RLock()
	for _, q := range r.Questions {
		if hit := c.lookup(q, w, now); !hit {
			miss = true
		}
	}
	c.mu.RUnlock()

	if !miss {
		return
	}

	if msg, err := w.Recur(ctx); err == nil && msg.RCode == NoError {
		c.insert(msg, now)
	}
}

// c.mu.RLock held
func (c *Cache) lookup(q Question, w MessageWriter, now time.Time) bool {
	var hit bool

	msg, ok := c.cache[q]
	if !ok {
		return false
	}

	for _, res := range msg.Answers {
		ttl := cacheTTL(res.TTL, now)
		if res.Name != q.Name || ttl <= 0 {
			continue
		}
		hit = true

		w.Answer(q.Name, ttl, res.Record)
	}
	for _, res := range msg.Authorities {
		ttl := cacheTTL(res.TTL, now)
		if res.Name != q.Name || ttl <= 0 {
			continue
		}
		hit = true

		w.Authority(q.Name, ttl, res.Record)
	}
	for _, res := range msg.Additionals {
		ttl := cacheTTL(res.TTL, now)
		if res.Name != q.Name || ttl <= 0 {
			continue
		}
		hit = true

		w.Additional(q.Name, ttl, res.Record)
	}

	return hit
}

func (c *Cache) insert(msg *Message, now time.Time) {
	cache := make(map[Question]*Message, len(msg.Questions))
	for _, q := range msg.Questions {
		m := new(Message)
		for _, res := range msg.Answers {
			if res.Name != q.Name {
				continue
			}

			res.TTL = cacheEpoch(res.TTL, now)
			m.Answers = append(m.Answers, res)
		}
		for _, res := range msg.Authorities {
			if res.Name != q.Name {
				continue
			}

			res.TTL = cacheEpoch(res.TTL, now)
			m.Authorities = append(m.Authorities, res)
		}
		for _, res := range msg.Additionals {
			if res.Name != q.Name {
				continue
			}

			res.TTL = cacheEpoch(res.TTL, now)
			m.Additionals = append(m.Additionals, res)
		}

		cache[q] = m
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cache == nil {
		c.cache = cache
		return
	}

	for q, m := range cache {
		c.cache[q] = m
	}
}

func cacheEpoch(ttl time.Duration, now time.Time) time.Duration {
	return time.Duration(now.Add(ttl).UnixNano())
}

func cacheTTL(epoch time.Duration, now time.Time) time.Duration {
	return time.Unix(0, int64(epoch)).Sub(now)
}
