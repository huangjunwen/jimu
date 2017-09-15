// Common interfaces/types that middlewares and utilites depend on.
package jimu

import (
	"context"
	"errors"
	"net/http"
)

// Logger interface comes from go-kit's log package.
// Also see: http://go-talks.appspot.com/github.com/ChrisHines/talks/structured-logging/structured-logging.slide#1
type Logger interface {
	Log(keyvals ...interface{}) error
}

// LoggerGetter gets Logger from context.
type LoggerGetter func(context.Context) Logger

// FallbackHandler is used for fallback response. Usually used for 4xx/5xx.
type FallbackHandler func(http.ResponseWriter, *http.Request, string, int)

// DefaultFallbackHandler == http.Error.
var DefaultFallbackHandler = func(w http.ResponseWriter, _ *http.Request, msg string, status int) {
	if status == 0 {
		status = http.StatusOK
	}
	if msg == "" {
		msg = http.StatusText(status)
	}
	http.Error(w, msg, status)
}

// Some common errors.
var (
	ErrComponentNotConfigured = errors.New("Component not configured")
	ErrComponentConfigured    = errors.New("Component configured")
)
