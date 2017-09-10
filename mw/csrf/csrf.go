package csrf

import (
	"fmt"
	"github.com/huangjunwen/jimu"
	"github.com/justinas/nosurf"
	"net/http"
)

// Token return the csrf token which can be then set to response.
func Token(r *http.Request) string {
	return nosurf.Token(r)
}

// Verify is used for manually verifying CSRF token.
func Verify(r *http.Request, sentToken string) bool {
	return nosurf.VerifyToken(nosurf.Token(r), sentToken)
}

// Option is the option of CsrfManager.
type Option func(*CsrfManager) error

// ManualVerify indicate that the handler will verify token manually (e.g. use Verify)
// Since the csrf token maybe sent in an unusual way (e.g. in some field in json body)
func ManualVerify() Option {
	return func(m *CsrfManager) error {
		m.manualVerify = true
		return nil
	}
}

// CookiePath set csrf cookie path. Default "/"
func CookiePath(path string) Option {
	return func(m *CsrfManager) error {
		m.cookie.Path = path
		return nil
	}
}

// CookieDomain set csrf cookie domain. Default not set.
func CookieDomain(domain string) Option {
	return func(m *CsrfManager) error {
		m.cookie.Domain = domain
		return nil
	}
}

// CookieMaxAge set csrf cookie max age. Default not set.
func CookieMaxAge(maxAge int) Option {
	return func(m *CsrfManager) error {
		m.cookie.MaxAge = maxAge
		return nil
	}
}

// CookieSecure set csrf cookie only used in https. Default false.
func CookieSecure() Option {
	return func(m *CsrfManager) error {
		m.cookie.Secure = true
		return nil
	}
}

// CookieNoHttpOnly unset csrf cookie's httpOnly flag. Default false.
func CookieNoHttpOnly() Option {
	return func(m *CsrfManager) error {
		m.cookie.HttpOnly = false
		return nil
	}
}

// FallbackHandler set the fallback handler for failure response.
func FallbackHandler(fallbackHandler jimu.FallbackHandler) Option {
	return func(m *CsrfManager) error {
		if fallbackHandler == nil {
			return fmt.Errorf("FallbackHandler is nil")
		}
		m.fallbackHandler = fallbackHandler
		return nil
	}
}

// CsrfManager use nosurf's double submit cookie to defense CSRF attack.
// Optional depends on fallback to render custom error page.
type CsrfManager struct {
	manualVerify    bool
	cookie          http.Cookie
	fallbackHandler jimu.FallbackHandler
}

// New create CsrfManager.
func New(options ...Option) (*CsrfManager, error) {

	ret := &CsrfManager{
		cookie: http.Cookie{
			Path:     "/",
			HttpOnly: true,
		},
		fallbackHandler: jimu.DefaultFallbackHandler,
	}
	for _, op := range options {
		if err := op(ret); err != nil {
			return nil, err
		}
	}
	return ret, nil

}

// Wrap is the middleware.
func (m *CsrfManager) Wrap(next http.Handler) http.Handler {

	mw := nosurf.New(next)
	mw.SetBaseCookie(m.cookie)
	if m.manualVerify {
		mw.ExemptFunc(func(*http.Request) bool {
			return true
		})
	}
	mw.SetFailureHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.fallbackHandler(w, r, &jimu.FallbackInfo{
			Status: http.StatusBadRequest,
			Msg:    http.StatusText(http.StatusBadRequest),
		})
	}))
	return mw

}
