package fallback

import (
	"context"
	"fmt"
	"github.com/rs/zerolog"
	"github.com/zenazn/goji/web/mutil"
	"net/http"
	"runtime/debug"
)

type fallbackCtxKeyType int

var (
	fallbackInfoCtxKey     = fallbackCtxKeyType(0)
	defaultFallbackHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fi := Info(r)
		status := fi.Status
		if status == 0 {
			status = http.StatusOK
		}
		msg := fi.Msg
		if msg == "" {
			msg = http.StatusText(status)
		}
		http.Error(w, msg, status)
	})
)

// FallbackInfo contains information to generate fallback response.
type FallbackInfo struct {
	Status int                         // For response. Default 200.
	Msg    string                      // For response. Default "".
	Values map[interface{}]interface{} // For response.
	Error  error                       // For logging
}

// Clear fallback information.
func (fi *FallbackInfo) Clear() {
	fi.Status = 0
	fi.Msg = ""
	fi.Values = map[interface{}]interface{}{}
	fi.Error = nil
}

// WithStatus set response status for fallback response.
func (fi *FallbackInfo) WithStatus(status int) *FallbackInfo {
	fi.Status = status
	return fi
}

// WithMsg set response msg for fallback response.
func (fi *FallbackInfo) WithMsg(msg string) *FallbackInfo {
	fi.Msg = msg
	return fi
}

// WithValue add arbitary key/value for fallback response.
func (fi *FallbackInfo) WithValue(key, val interface{}) *FallbackInfo {
	fi.Values[key] = val
	return fi
}

// WithError set error for logging.
func (fi *FallbackInfo) WithError(err error) *FallbackInfo {
	fi.Error = err
	return fi
}

// Info retrive FallbackInfo from request's context or nil if not exists.
// One can set fallback information like:
//
//   func MyHandler(w http.ResponseWriter, r *http.Request) {
//   	// ...
//   	if somethingWrong {
//   		fallback.Info(r).WithError(err).WithStatus(500).WithMsg("Something bad happened")
//   		return
//   	}
//   }
//
func Info(r *http.Request) *FallbackInfo {
	val := r.Context().Value(fallbackInfoCtxKey)
	if val == nil {
		return nil
	}
	return val.(*FallbackInfo)
}

// Option is FallbackManager's option.
type Option func(*FallbackManager) error

// Handler set the fallback handler.
func Handler(h http.Handler) Option {
	if h == nil {
		h = defaultFallbackHandler
	}
	return func(m *FallbackManager) error {
		m.fallbackHandler = h
		return nil
	}
}

// HandlerFunc set the fallback handler.
func HandlerFunc(f http.HandlerFunc) Option {
	var h http.Handler = f
	if h == nil {
		h = defaultFallbackHandler
	}
	return func(m *FallbackManager) error {
		m.fallbackHandler = h
		return nil
	}
}

// FallbackManager adds a fallback handler to context which will be invoked
// when panic or no other response written. User handler can also add extra information to
// configure how to generate fallback response.
type FallbackManager struct {
	fallbackHandler http.Handler
}

// NewFallbackManager create FallbackManager with options.
func NewFallbackManager(options ...Option) (*FallbackManager, error) {

	ret := &FallbackManager{}
	ops := []Option{
		Handler(nil),
	}
	ops = append(ops, options...)
	for _, op := range ops {
		if err := op(ret); err != nil {
			return nil, err
		}
	}
	return ret, nil
}

// Wrap is the middleware.
func (m *FallbackManager) Wrap(next http.Handler) http.Handler {

	fallbackHandler := m.fallbackHandler

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		var (
			w2 mutil.WriterProxy
			r2 *http.Request
			fi = &FallbackInfo{}
			ok bool
			lg = zerolog.Ctx(r.Context())
		)

		// Wrap ResponseWriter to check status.
		if w2, ok = w.(mutil.WriterProxy); !ok {
			w2 = mutil.WrapWriter(w)
		}

		// Install fallback context value.
		r2 = r.WithContext(context.WithValue(r.Context(), fallbackInfoCtxKey, fi))

		defer func() {
			hasPanic := false
			rcv := recover()

			// If panic.
			if rcv != nil {
				hasPanic = true
				err, ok := rcv.(error)
				if !ok {
					err = fmt.Errorf("%v", rcv)
				}
				fi.Clear()
				fi.WithError(err).
					WithStatus(http.StatusInternalServerError).
					WithMsg(http.StatusText(http.StatusInternalServerError))
			}

			// Log if has Error.
			if fi.Error != nil {
				ev := lg.Error().Err(fi.Error).Str("src", "fallback")
				if hasPanic {
					ev.Bytes("panic", debug.Stack())
				}
				ev.Msg("")
			}

			// If w2.Status() == 0, then w2.WriteHeader is not called. Activate
			// fallback handler.
			if w2.Status() == 0 {
				fallbackHandler.ServeHTTP(w2, r2)
			}

		}()

		next.ServeHTTP(w2, r2)

	})

}
