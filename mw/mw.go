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

// ErrHandler is used to response errors (e.g. 4xx/5xx).
type ErrHandler func(w http.ResponseWriter, r *http.Request, msg string, code int)

// DefaultErrHandler == http.Error
var DefaultErrHandler = func(w http.ResponseWriter, _ *http.Request, msg string, code int) {
	http.Error(w, msg, code)
	return
}
