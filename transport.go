package firebase

import (
	"net/http"

	"golang.org/x/net/context"
)

// HTTPClient is the context key to use with golang.org/x/net/context's
// WithValue function to associate an *http.Client value with a context.
var HTTPClient ContextKey

// ContextKey is just an empty struct. It exists so HTTPClient can be
// an immutable public variable with a unique type. It's immutable
// because nobody else can create a ContextKey, being unexported.
type ContextKey struct{}

// RequestContextFunc is a func which tries to return a context.Context
// given a Request value. If it returns an error, the search stops
// with that error.  If it returns (nil, nil), the search continues
// down the list of registered funcs.
type RequestContextFunc func(*http.Request) (context.Context, error)

var requestContextFuncs []RequestContextFunc

func RegisterRequestContextFunc(fn RequestContextFunc) {
	requestContextFuncs = append(requestContextFuncs, fn)
}

func RequestContext(req *http.Request) (context.Context, error) {
	for _, fn := range requestContextFuncs {
		ctx, err := fn(req)
		if err != nil {
			return nil, err
		}
		if ctx != nil {
			return ctx, nil
		}
	}
	return context.Background(), nil
}

// ContextClientFunc is a func which tries to return an *http.Client
// given a Context value. If it returns an error, the search stops
// with that error.  If it returns (nil, nil), the search continues
// down the list of registered funcs.
type ContextClientFunc func(context.Context) (*http.Client, error)

var contextClientFuncs []ContextClientFunc

func RegisterContextClientFunc(fn ContextClientFunc) {
	contextClientFuncs = append(contextClientFuncs, fn)
}

func ContextClient(ctx context.Context) (*http.Client, error) {
	if ctx != nil {
		if hc, ok := ctx.Value(HTTPClient).(*http.Client); ok {
			return hc, nil
		}
	}
	for _, fn := range contextClientFuncs {
		c, err := fn(ctx)
		if err != nil {
			return nil, err
		}
		if c != nil {
			return c, nil
		}
	}
	return http.DefaultClient, nil
}

func ContextTransport(ctx context.Context) http.RoundTripper {
	hc, err := ContextClient(ctx)
	// This is a rare error case (somebody using nil on App Engine).
	if err != nil {
		return ErrorTransport{err}
	}
	return hc.Transport
}

// ErrorTransport returns the specified error on RoundTrip.
// This RoundTripper should be used in rare error cases where
// error handling can be postponed to response handling time.
type ErrorTransport struct{ Err error }

func (t ErrorTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, t.Err
}
