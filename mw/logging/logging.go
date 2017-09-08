package logging

import (
	"fmt"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

type ZeroLogger *zerolog.Logger

func asString(v interface{}) string {
	s, ok := v.(string)
	if ok {
		return s
	}
	return fmt.Sprint(v)
}

// Log implement mw.Logger interface.
func (l ZeroLogger) Log(keyvals ...interface{}) error {

	lg := (*zerolog.Logger)(l)

	if len(keyvals)&1 == 1 {
		keyvals = append(keyvals, "(!!missing)")
	}

	var (
		ev  *zerolog.Event
		msg string
	)

	for i := 0; i < len(keyvals); i += 2 {
		key := asString(keyvals[i])
		val := keyvals[i+1]
		switch key {
		// Expect the first field is level. Otherwise default level to info.
		case zerolog.LevelFieldName:
			if ev != nil {
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
	ev.Msg(msg)

	return nil

}

// Write implement chi/middleware#LogEntry interface.
func (l ZeroLogger) Write(code, sz int, dur time.Duration) {
	lg := (*zerolog.Logger)(l)
	lg.Info().Int("code", code).Int("sz", sz).Dur("dur", dur).Str("src", "http").Msg("")
}

// Write implement chi/middleware#LogEntry interface.
func (l ZeroLogger) Panic(v interface{}, stack []byte) {
	lg := (*zerolog.Logger)(l)
	lg.Error().Interface("panic", v).Bytes("tb", stack).Str("src", "http").Msg("")
}
