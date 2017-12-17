package dns

import (
	"context"
)

// Handler responds to a DNS query.
//
// ServeDNS should build the reply message using the MessageWriter, and may
// optionally call the Reply method. Returning signals that the request is
// finished and the response is ready to send.
//
// A recursive handler may call the Recur method of the MessageWriter to send
// an query upstream. Only unanswered questions are included in the upstream
// query.
type Handler interface {
	ServeDNS(context.Context, MessageWriter, *Query)
}

// The HandlerFunc type is an adapter to allow the use of ordinary functions as
// DNS handlers. If f is a function with the appropriate signature,
// HandlerFunc(f) is a Handler that calls f.
type HandlerFunc func(context.Context, MessageWriter, *Query)

// ServeDNS calls f(w, r).
func (f HandlerFunc) ServeDNS(ctx context.Context, w MessageWriter, r *Query) {
	f(ctx, w, r)
}

// Refuse responds to all queries with a "Query Refused" message.
func Refuse(ctx context.Context, w MessageWriter, r *Query) {
	w.Status(Refused)
}
