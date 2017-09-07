package logging

import (
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

// Option is LoggingManager's option.
type Option func(*LoggingManager) error

// Output set logging's output.
func Output(w io.Writer) Option {
	if w == nil {
		w = os.Stderr
	}
	return func(m *LoggingManager) error {
		m.output = w
		return nil
	}
}

// ConsoleOutput set logging's using zerolog.ConsoleWriter.
func ConsoleOutput(w io.Writer, noColor bool) Option {
	if w == nil {
		w = os.Stderr
	}
	return func(m *LoggingManager) error {
		m.output = zerolog.ConsoleWriter{Out: w, NoColor: noColor}
		return nil
	}
}

// ExtraField add an extra field to log for a http request.
func ExtraField(field string, fieldExtractor func(*http.Request) string) Option {
	return func(m *LoggingManager) error {
		m.fields = append(m.fields, field)
		m.fieldExtractors = append(m.fieldExtractors, fieldExtractor)
		return nil
	}
}

// LoggingManager adds zerolog's json logger to context and log http requests.
type LoggingManager struct {
	output          io.Writer
	fields          []string
	fieldExtractors []func(*http.Request) string
	logger          zerolog.Logger
}

// NewLoggingManager create LoggingManager with options.
func NewLoggingManager(options ...Option) (*LoggingManager, error) {

	ret := &LoggingManager{}
	ops := []Option{
		Output(nil),
	}
	ops = append(ops, options...)
	for _, op := range ops {
		if err := op(ret); err != nil {
			return nil, err
		}
	}

	ret.logger = zerolog.New(ret.output).With().Timestamp().Logger()
	return ret, nil

}

// Wrap is the middleware.
func (m *LoggingManager) Wrap(next http.Handler) http.Handler {

	mw1 := hlog.NewHandler(m.logger)
	mw2 := hlog.AccessHandler(func(r *http.Request, status int, sz int, duration time.Duration) {
		// Do this ourself to reduce one level of middleware.
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = "?.?.?.?"
		}
		ev := m.logger.Info().
			Str("ip", ip).
			Str("method", r.Method).
			Str("url", r.URL.String()).
			Int("status", status).
			Int("sz", sz).
			Str("src", "http").
			Str("dur", duration.String())
		for i, field := range m.fields {
			v := m.fieldExtractors[i](r)
			if v != "" {
				ev = ev.Str(field, v)
			}
		}
		ev.Msg("")

	})
	mw3 := hlog.RequestIDHandler("reqid", "")

	return mw1(mw2(mw3(next)))
}
