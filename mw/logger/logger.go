package logger

import (
	"context"
	"fmt"
	"github.com/huangjunwen/MW/mw"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

// Logger adapt zerolog's logger to Logger interface.
type Logger zerolog.Logger

func asString(v interface{}) string {
	s, ok := v.(string)
	if ok {
		return s
	}
	return fmt.Sprint(v)
}

// Log implement mw.Logger interface. NOTE: the first key/value pair should
// be ("level", "debug"/"info"/"warn"...), otherwise the level will set to
// "info" even it appears later.
func (l *Logger) Log(keyvals ...interface{}) error {

	var (
		lg  = (*zerolog.Logger)(l)
		ev  *zerolog.Event
		msg string
	)

	odd := false
	n := len(keyvals)
	if len(keyvals)&1 == 1 {
		odd = true
		n -= 1
	}

	for i := 0; i < n; i += 2 {
		key := asString(keyvals[i])
		val := keyvals[i+1]
		switch key {
		// Expect the first field is level. Otherwise default level to info.
		case zerolog.LevelFieldName:
			if ev != nil {
				// Skip "level" since log event has been created.
				continue
			}
			switch asString(val) {
			case "debug":
				ev = lg.Debug()
			case "info":
				ev = lg.Info()
			case "warn":
				ev = lg.Warn()
			case "error":
				ev = lg.Error()
			case "fatal":
				ev = lg.Fatal()
			case "panic":
				ev = lg.Panic()
			default:
			}
		default:
			if ev == nil {
				ev = lg.Info()
			}
			switch key {
			case zerolog.MessageFieldName:
				msg = asString(val)
			default:
				ev = ev.Interface(key, val)
			}
		}
	}

	if odd {
		ev = ev.Str(asString(keyvals[n]), "(!!value missing)")
	}
	ev.Msg(msg)

	return nil

}

// Option is the option in createing LoggerManager.
type Option func(*LoggerManager) error

// Output set logging's output.
func Output(w io.Writer) Option {
	if w == nil {
		w = os.Stderr
	}
	return func(m *LoggerManager) error {
		m.output = w
		return nil
	}
}

// ConsoleOutput set logging's using zerolog.ConsoleWriter.
func ConsoleOutput(w io.Writer, noColor bool) Option {
	if w == nil {
		w = os.Stderr
	}
	return func(m *LoggerManager) error {
		m.output = zerolog.ConsoleWriter{Out: w, NoColor: noColor}
		return nil
	}
}

// ExtraField add an extra field to log for a http request.
func ExtraField(field string, fieldExtractor func(*http.Request) string) Option {
	return func(m *LoggerManager) error {
		m.fields = append(m.fields, field)
		m.fieldExtractors = append(m.fieldExtractors, fieldExtractor)
		return nil
	}
}

// LoggerManager adds zerolog's json logger to context and log http requests.
type LoggerManager struct {
	output          io.Writer
	fields          []string
	fieldExtractors []func(*http.Request) string
	logger          zerolog.Logger
}

// New create LoggerManager with options.
func New(options ...Option) (*LoggerManager, error) {

	ret := &LoggerManager{}
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
func (m *LoggerManager) Wrap(next http.Handler) http.Handler {

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

// FromCtx implement mw.LoggerGetter
func FromCtx(ctx context.Context) mw.Logger {
	return (*Logger)(zerolog.Ctx(ctx))
}
