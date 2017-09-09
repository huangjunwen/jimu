// Some common types and interfaces middlewares depend on.
package mw

import (
	"context"
	"net/http"
)

// Logger interface comes from go-kit's log package.
// Also see: http://go-talks.appspot.com/github.com/ChrisHines/talks/structured-logging/structured-logging.slide#1
type Logger interface {
	Log(keyvals ...interface{}) error
}

// LoggerGetter gets Logger from context.
type LoggerGetter func(context.Context) Logger

// FallbackHandler is the secondary handler. Usually used in response errors.
type FallbackHandler func(w http.ResponseWriter, r *http.Request, msg string, code int)

// FallbackHandlerGetter gets FallbackHandler from context.
type FallbackHandlerGetter func(context.Context) FallbackHandler

// DefaultFallbackHandler == http.Error
var DefaultFallbackHandler = func(w http.ResponseWriter, _ *http.Request, msg string, code int) {
	if msg == "" {
		msg = http.StatusText(code)
	}
	http.Error(w, msg, code)
	return
}

// FallbackRoute defines a route rule for fallback handler.
type FallbackRoute struct {
	Path    string
	Handler FallbackHandler
}
