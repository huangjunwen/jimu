// Some common types and interfaces.
package jimu

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

// FallbackInfo is used to store information of fallback response.
type FallbackInfo struct {
	Status int
	Msg    string
	Data   map[interface{}]interface{}
}

// FallbackHandler is used for fallback response.
type FallbackHandler func(http.ResponseWriter, *http.Request, *FallbackInfo)

// DefaultFallbackHandler use http.Error to response.
var DefaultFallbackHandler = func(w http.ResponseWriter, _ *http.Request, fi *FallbackInfo) {
	status := fi.Status
	if status == 0 {
		status = http.StatusOK
	}
	msg := fi.Msg
	if msg == "" {
		msg = http.StatusText(status)
	}
	http.Error(w, msg, status)
}
