package recover

import (
	"fmt"
	"github.com/huangjunwen/jimu"
	"github.com/zenazn/goji/web/mutil"
	"net/http"
	"runtime/debug"
)

// Option is the option in creating RecoverManager.
type Option func(*RecoverManager) error

// LoggerGetter set the LoggerGetter for RecoverManager.
func LoggerGetter(loggerGetter jimu.LoggerGetter) Option {
	return func(m *RecoverManager) error {
		if loggerGetter == nil {
			return fmt.Errorf("LoggerGetter is nil")
		}
		m.loggerGetter = loggerGetter
		return nil
	}
}

// FallbackHandler set the FallbackHandler for RecoverManager.
func FallbackHandler(fallbackHandler jimu.FallbackHandler) Option {
	return func(m *RecoverManager) error {
		if fallbackHandler == nil {
			return fmt.Errorf("FallbackHandler is nil")
		}
		m.fallbackHandler = fallbackHandler
		return nil
	}
}

// RecoverManager recover from panic.
type RecoverManager struct {
	loggerGetter    jimu.LoggerGetter
	fallbackHandler jimu.FallbackHandler
}

// New creates RecoverManager with options.
func New(options ...Option) (*RecoverManager, error) {

	ret := &RecoverManager{
		fallbackHandler: jimu.DefaultFallbackHandler,
	}
	for _, op := range options {
		if err := op(ret); err != nil {
			return nil, err
		}
	}
	if ret.loggerGetter == nil {
		return nil, fmt.Errorf("Missing LoggerGetter")
	}
	return ret, nil
}

// Wrap is the middleware.
func (m *RecoverManager) Wrap(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		var (
			lg = m.loggerGetter(r.Context())
			w2 mutil.WriterProxy
			ok bool
		)

		// Wrap ResponseWriter to check status.
		if w2, ok = w.(mutil.WriterProxy); !ok {
			w2 = mutil.WrapWriter(w)
		}

		defer func() {

			// If panic.
			if rcv := recover(); rcv != nil {
				lg.Log(
					"level", "error",
					"src", "recover",
					"error", rcv,
					"tb", string(debug.Stack()),
				)
			}

			// Response 500 only when w2 has not wrote.
			if w2.Status() == 0 {
				m.fallbackHandler(w2, r, &jimu.FallbackInfo{
					Status: http.StatusInternalServerError,
					Msg:    http.StatusText(http.StatusInternalServerError),
				})
			}

		}()

		// Pass to next.
		next.ServeHTTP(w2, r)

	})

}
