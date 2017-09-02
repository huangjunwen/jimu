package csrf

import (
	"github.com/huangjunwen/MW/mw/fallback"
	"github.com/justinas/nosurf"
	"net/http"
)

var (
	defaultCsrfBaseCookie = &http.Cookie{
		HttpOnly: true,
		Path:     "/",
	}
)

// Token return the csrf token for setting.
func Token(r *http.Request) string {
	return nosurf.Token(r)
}

// Verify is used for manually verifying CSRF token.
func Verify(r *http.Request, sentToken string) bool {
	return nosurf.VerifyToken(nosurf.Token(r), sentToken)
}

// New creates a middleware to prevent CSRF attack using nosurf's double submit cookie.
//
// Depends on: (optinal) mw/fallback for custom error response.
func New(manual bool, baseCookie *http.Cookie) func(http.Handler) http.Handler {

	if baseCookie == nil {
		baseCookie = defaultCsrfBaseCookie
	}

	return func(next http.Handler) http.Handler {
		mw := nosurf.New(next)
		mw.SetBaseCookie(*baseCookie)
		if manual {
			mw.ExemptFunc(func(*http.Request) bool {
				return true
			})
		}
		mw.SetFailureHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fi := fallback.Info(r)
			if fi != nil {
				fi.WithStatus(http.StatusBadRequest)
				return
			}
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		}))
		return mw
	}

}
