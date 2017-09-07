package router

import (
	"context"
	"fmt"
	"github.com/huangjunwen/MW/mw/fallback"
	"github.com/julienschmidt/httprouter"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
)

type paramsCtxKeyType int

var paramsCtxKey = paramsCtxKeyType(0)

// Router is a thin wrapper of httprouter.Router
// Waiting for https://github.com/julienschmidt/httprouter/pull/147.
type Router struct {
	*httprouter.Router
}

// New create a new Router.
func New() *Router {
	ret := &Router{
		Router: httprouter.New(),
	}

	ret.Router.NotFound = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fi := fallback.Info(r)
		if fi == nil {
			http.NotFound(w, r)
			return
		}
		fi.WithStatus(http.StatusNotFound)
		return
	})

	ret.Router.MethodNotAllowed = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fi := fallback.Info(r)
		if fi == nil {
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
		fi.WithStatus(http.StatusMethodNotAllowed)
		return
	})

	return ret
}

// Handler regist http.Handler to the router.
func (r *Router) Handler(method, pathPattern string, h http.Handler) {
	r.Router.Handle(method, pathPattern,
		func(w http.ResponseWriter, req *http.Request, params httprouter.Params) {
			h.ServeHTTP(w, req.WithContext(context.WithValue(req.Context(), paramsCtxKey, params)))
		},
	)
}

// HandlerFunc regist http.HandlerFunc to the router.
func (r *Router) HandlerFunc(method, pathPattern string, h http.HandlerFunc) {
	r.Handler(method, pathPattern, h)
}

// ServeHTTP implement http.Handler interface.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.Router.ServeHTTP(w, req)
}

// ParamsFromContext extract path params.
func ParamsFromContext(ctx context.Context) httprouter.Params {
	p, _ := ctx.Value(paramsCtxKey).(httprouter.Params)
	return p
}

var (
	paramRe         = regexp.MustCompile(`[:\*][a-zA-Z][a-zA-Z_0-9]*`)
	BadPathPattern  = fmt.Errorf("Bad path pattern")
	NotEnoughParams = fmt.Errorf("Not enough params to substitute")
	TooManyparams   = fmt.Errorf("Too many params to substitute")
)

// BuildPath is the reverse of matching: substitute ":name" and "*name"
// Params are Sprint into string.
func BuildPath(pathPattern string, params ...interface{}) (string, error) {

	var err error
	var wildcard string
	i := 0
	ret := paramRe.ReplaceAllStringFunc(pathPattern, func(origin string) string {
		if i >= len(params) {
			err = NotEnoughParams
			return ""
		}
		s := fmt.Sprint(params[i])
		i += 1
		// '*' case.
		// Wildcard is a path, should use path.Join instead simply substitute.
		if origin[0] == '*' {
			wildcard = s
			return ""
		}
		// ':'
		// Wildcard has already encountered.
		if wildcard != "" {
			err = BadPathPattern
			return ""
		}
		return url.PathEscape(s)

	})
	if err != nil {
		return "", err
	}
	if i < len(params) {
		return "", TooManyparams
	}
	if wildcard == "" {
		return ret, nil
	}
	wildcardParts := strings.Split(wildcard, "/")
	for i = 0; i < len(wildcardParts); i++ {
		wildcardParts[i] = url.PathEscape(wildcardParts[i])
	}
	return path.Join(ret, path.Join(wildcardParts...)), nil

}

// BuildPath is the reverse of matching: substitute ":name" and "*name"
func BuildPathFromParams(pathPattern string, params httprouter.Params) (string, error) {
	ps := make([]interface{}, len(params))
	for i, p := range params {
		ps[i] = p.Value
	}
	return BuildPath(pathPattern, ps...)
}
