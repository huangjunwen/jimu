package fallback

import (
	"context"
	"fmt"
	"github.com/huangjunwen/MW/mw"
	"github.com/naoina/denco"
	"github.com/zenazn/goji/web/mutil"
	"net/http"
	"runtime/debug"
)

type fallbackCtxKeyType int

var fallbackCtxKey = fallbackCtxKeyType(0)

// Option is the option in creating FallbackManager.
type Option func(*FallbackManager) error

// Route regists a collection of fallback routes.
func Routes(routes ...mw.FallbackRoute) Option {
	return func(m *FallbackManager) error {
		for _, route := range routes {
			m.routeRecords = append(m.routeRecords, denco.Record{route.Path, route.Handler})
		}
		return nil
	}
}

// LoggerGetter set the LoggerGetter for FallbackManager.
func LoggerGetter(loggerGetter mw.LoggerGetter) Option {
	return func(m *FallbackManager) error {
		if loggerGetter == nil {
			return fmt.Errorf("LoggerGetter is nil")
		}
		m.loggerGetter = loggerGetter
		return nil
	}
}

// FallbackManager is used to regist fallback handlers.
type FallbackManager struct {
	routeRecords []denco.Record
	route        *denco.Router
	loggerGetter mw.LoggerGetter
}

// New create FallbackManager with options.
func New(options ...Option) (*FallbackManager, error) {

	ret := &FallbackManager{}
	for _, op := range options {
		if err := op(ret); err != nil {
			return nil, err
		}
	}
	ret.route = denco.New()
	err := ret.route.Build(ret.routeRecords)
	if err != nil {
		return nil, err
	}
	return ret, nil

}

// Serve implement FallbackHandler: it dispatch request to registed fallback handlers.
func (m *FallbackManager) Serve(w http.ResponseWriter, r *http.Request, msg string, code int) {

	data, _, found := m.route.Lookup(r.URL.Path)
	if !found {
		mw.DefaultFallbackHandler(w, r, msg, code)
		return
	}
	data.(mw.FallbackHandler)(w, r, msg, code)
	return

}

// Wrap is the middleware. It regist the fallback handlers in context.
func (m *FallbackManager) Wrap(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		var (
			lg = m.loggerGetter(r.Context())
			w2 mutil.WriterProxy
			r2 *http.Request
			ok bool
		)

		// Wrap ResponseWriter to check status.
		if w2, ok = w.(mutil.WriterProxy); !ok {
			w2 = mutil.WrapWriter(w)
		}

		// Install fallback handler to context.
		r2 = r.WithContext(context.WithValue(r.Context(), fallbackCtxKey, m.Serve))

		defer func() {

			// If panic.
			if rcv := recover(); rcv != nil {
				lg.Log(
					"level", "error",
					"src", "fallback",
					"error", rcv,
					"tb", string(debug.Stack()),
				)
			}

			// If w2.Status() == 0, then w2.WriteHeader is not called.
			if w2.Status() == 0 {
				code := http.StatusInternalServerError
				m.Serve(w2, r2, http.StatusText(code), code)
			}

		}()

		// Pass to next.
		next.ServeHTTP(w2, r2)

	})

}

// FromCtx implement mw.FallbackHandlerGetter.
func FromCtx(ctx context.Context) mw.FallbackHandler {
	v := ctx.Value(fallbackCtxKey)
	if v == nil {
		return nil
	}
	return v.(mw.FallbackHandler)
}
