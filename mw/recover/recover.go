package recover

import (
	"fmt"
	"github.com/huangjunwen/jimu"
	"github.com/zenazn/goji/web/mutil"
	"net/http"
	"runtime/debug"
)

// Option is the option of RecoverManager.
type Option func(*RecoverManager) error

// LoggerGetter set the LoggerGetter for RecoverManager. (required)
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
	options         []Option
	loggerGetter    jimu.LoggerGetter
	fallbackHandler jimu.FallbackHandler
}

// New creates RecoverManager.
func New() *RecoverManager {
	return &RecoverManager{
		options: []Option{
			FallbackHandler(jimu.DefaultFallbackHandler),
		},
	}
}

func (m *RecoverManager) configured() bool {
	return m.fallbackHandler != nil
}

// Options add options to the manager.
func (m *RecoverManager) Options(options ...Option) {
	if m.configured() {
		panic(jimu.ErrComponentConfigured)
	}
	m.options = append(m.options, options...)
}

// Configure the manager. Options are not allowed to add after configure.
func (m *RecoverManager) Configure() error {

	if m.configured() {
		panic(jimu.ErrComponentConfigured)
	}
	for _, op := range m.options {
		if err := op(m); err != nil {
			return err
		}
	}
	if m.loggerGetter == nil {
		return fmt.Errorf("Missing LoggerGetter")
	}
	return nil
}

// Wrap is the middleware.
func (m *RecoverManager) Wrap(next http.Handler) http.Handler {

	if !m.configured() {
		panic(jimu.ErrComponentNotConfigured)
	}

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
				m.fallbackHandler(w2, r, http.StatusText(http.StatusInternalServerError),
					http.StatusInternalServerError)
			}

		}()

		// Pass to next.
		next.ServeHTTP(w2, r)

	})

}
