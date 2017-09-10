package router

import (
	"context"
	"fmt"
	"github.com/huangjunwen/MW/mw"
	"github.com/naoina/denco"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
)

type paramsCtxKeyType int

var paramsCtxKey = paramsCtxKeyType(0)

// Router is a wrapper around denco's router.
type Router struct {
	// path -> method -> handler
	handlerEntires map[string]map[string]http.Handler
	router         *denco.Router

	// Set fallback handler for router.
	mw.FallbackHandler
}

// New creates a Router.
func New() *Router {
	return &Router{
		handlerEntires:  map[string]map[string]http.Handler{},
		FallbackHandler: mw.DefaultFallbackHandler,
	}
}

// Handler add an http handler to the router.
func (r *Router) Handler(path string, handler http.Handler, methods ...string) {

	for _, method := range methods {
		method = strings.ToUpper(method)
		if _, found := r.handlerEntires[path]; !found {
			r.handlerEntires[path] = map[string]http.Handler{}
		}
		r.handlerEntires[path][method] = handler
	}

}

// HandlerFunc add an http handler func to the router.
func (r *Router) HandlerFunc(path string, handlerFunc http.HandlerFunc, methods ...string) {
	r.Handler(path, handlerFunc, methods...)
}

// Build construct/re-construct router.
func (r *Router) Build() error {

	records := []denco.Record{}
	for path, data := range r.handlerEntires {
		records = append(records, denco.Record{
			Key:   path,
			Value: data,
		})
	}

	router := denco.New()
	if err := router.Build(records); err != nil {
		return err
	}
	r.router = router

	return nil

}

// ServeHTTP implement http.Handler.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {

	data, params, found := r.router.Lookup(req.URL.Path)
	if !found {
		r.FallbackHandler(w, req, &mw.FallbackInfo{
			Status: http.StatusNotFound,
			Msg:    http.StatusText(http.StatusNotFound),
		})
		return
	}

	handler, found2 := data.(map[string]http.Handler)[req.Method]
	if !found2 {
		r.FallbackHandler(w, req, &mw.FallbackInfo{
			Status: http.StatusMethodNotAllowed,
			Msg:    http.StatusText(http.StatusMethodNotAllowed),
		})
		return
	}

	req = req.WithContext(context.WithValue(req.Context(), paramsCtxKey, params))
	handler.ServeHTTP(w, req)
	return
}

// ParamsFromContext extract path params.
func ParamsFromContext(ctx context.Context) denco.Params {
	p, _ := ctx.Value(paramsCtxKey).(denco.Params)
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
