package logger

import (
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

// Logger return the zerologger (or a nop logger) for current request.
func Logger(r *http.Request) zerolog.Logger {
	return zerolog.Ctx(r.Context())
}

// New creates a middleware that adds zerolog's json logger to context.
//
// Depends on: None
func New(output io.Writer) func(http.Handler) http.Handler {

	if output == nil {
		output = os.Stderr
	}
	logger := zerolog.New(output).With().Timestamp().Logger()

	mw1 := hlog.NewHandler(logger)
	mw2 := hlog.AccessHandler(func(r *http.Request, status int, sz int, duration time.Duration) {
		// Do this ourself to reduce one level of middleware.
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = "?.?.?.?"
		}
		hlog.FromRequest(r).Info().
			Str("ip", ip).
			Str("method", r.Method).
			Str("url", r.URL.String()).
			Int("status", status).
			Int("sz", sz).
			Str("src", "http").
			Str("dur", duration.String()).Msg("")

	})
	mw3 := hlog.RequestIDHandler("reqid", "")

	return func(next http.Handler) http.Handler {
		return mw1(mw2(mw3(next)))
	}

}

// NewForConsole is similar to New but wrap output with zerolog.ConsoleWriter for
// human readable.
func NewForConsole(output io.Writer, noColor bool) func(http.Handler) http.Handler {
	if output == nil {
		output = os.Stderr
	}
	return New(zerolog.ConsoleWriter{Out: output, NoColor: noColor})
}
