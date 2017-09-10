package router

import (
	"context"
	"fmt"
	"github.com/huangjunwen/jimu"
	"github.com/naoina/denco"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
)

type paramsCtxKeyType int

var paramsCtxKey = paramsCtxKeyType(0)

// ParamsFromContext extract path params.
func ParamsFromContext(ctx context.Context) denco.Params {
	p, _ := ctx.Value(paramsCtxKey).(denco.Params)
	return p
}

// Router is a wrapper around denco's router.
type Router struct {
	// path -> method -> handler
	handlerEntires map[string]map[string]http.Handler
	router         *denco.Router

	// Set fallback handler for router.
	jimu.FallbackHandler
}

// New creates a Router.
func New() *Router {
	return &Router{
		handlerEntires:  map[string]map[string]http.Handler{},
		FallbackHandler: jimu.DefaultFallbackHandler,
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

	if r.router == nil {
		panic(fmt.Errorf("Router is not built."))
	}

	data, params, found := r.router.Lookup(req.URL.Path)
	if !found {
		r.FallbackHandler(w, req, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}

	handler, found2 := data.(map[string]http.Handler)[req.Method]
	if !found2 {
		r.FallbackHandler(w, req, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	req = req.WithContext(context.WithValue(req.Context(), paramsCtxKey, params))
	handler.ServeHTTP(w, req)
	return
}

// FallbackRouter is used to regist fallback handlers.
type FallbackRouter struct {
	// path -> handler
	handlerEntires map[string]jimu.FallbackHandler
	router         *denco.Router
}

// NewFallbackRouter creates a FallbackRouter.
func NewFallbackRouter() *FallbackRouter {
	return &FallbackRouter{
		handlerEntires: map[string]jimu.FallbackHandler{},
	}
}

// Handler add a FallbackHandler to the router.
func (r *FallbackRouter) Handler(path string, handler jimu.FallbackHandler) {
	r.handlerEntires[path] = handler
}

// Build construct/re-construct router.
func (r *FallbackRouter) Build() error {

	records := []denco.Record{}
	for path, handler := range r.handlerEntires {
		records = append(records, denco.Record{
			Key:   path,
			Value: handler,
		})
	}

	router := denco.New()
	if err := router.Build(records); err != nil {
		return err
	}
	r.router = router

	return nil
}

// Serve implement FallbackHandler.
func (r *FallbackRouter) Serve(w http.ResponseWriter, req *http.Request, msg string, status int) {

	if r.router == nil {
		panic(fmt.Errorf("Router is not built."))
	}

	data, params, found := r.router.Lookup(req.URL.Path)
	req = req.WithContext(context.WithValue(req.Context(), paramsCtxKey, params))
	if !found {
		jimu.DefaultFallbackHandler(w, req, msg, status)
		return
	}
	data.(jimu.FallbackHandler)(w, req, msg, status)
	return
}

var (
	paramRe         = regexp.MustCompile(`[:\*][a-zA-Z][a-zA-Z_0-9]*`)
	BadPathPattern  = fmt.Errorf("Bad path pattern")
	NotEnoughParams = fmt.Errorf("Not enough params to substitute")
	TooManyparams   = fmt.Errorf("Too many params to substitute")
)

// BuildPath is the reverse of matching:
//   BuildPath("/do/:action/at/*location", "clean", "room/1") -> "/do/clean/at/room/1"
// Params can be string, denco.Param or any Sprint-able object.
func BuildPath(pathPattern string, params ...interface{}) (string, error) {

	var err error
	var wildcard string
	i := 0
	ret := paramRe.ReplaceAllStringFunc(pathPattern, func(origin string) string {
		if i >= len(params) {
			err = NotEnoughParams
			return ""
		}
		var s string
		switch v := params[i].(type) {
		case string:
			s = v
		case denco.Param:
			s = v.Value
		default:
			s = fmt.Sprint(v)
		}
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
