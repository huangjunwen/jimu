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

// unescapeParams unescape path params.
func unescapeParams(params denco.Params) error {
	for i := 0; i < len(params); i++ {
		s, err := url.PathUnescape(params[i].Value)
		if err != nil {
			return err
		}
		params[i].Value = s
	}
	return nil
}

// Option for configuring Router.
type Option func(*Router) error

// FallbackHandler set the fallback handler (for 404 ...) for the router.
func FallbackHandler(fallbackHandler jimu.FallbackHandler) Option {
	return func(r *Router) error {
		r.fallbackHandler = fallbackHandler
		return nil
	}
}

// Router is a wrapper around denco's router.
type Router struct {
	// path -> method -> handler
	handlerEntires map[string]map[string]http.Handler
	router         *denco.Router

	options         []Option
	fallbackHandler jimu.FallbackHandler
}

// New creates a Router.
func New() *Router {
	return &Router{
		handlerEntires: map[string]map[string]http.Handler{},
		options: []Option{
			FallbackHandler(jimu.DefaultFallbackHandler),
		},
	}
}

func (r *Router) configured() bool {
	return r.router != nil
}

// Options add options for the router.
func (r *Router) Options(options ...Option) {
	if r.configured() {
		panic(jimu.ErrComponentConfigured)
	}
	r.options = append(r.options, options...)
}

// Handler add an http handler to the router.
func (r *Router) Handler(path string, handler http.Handler, methods ...string) {

	if r.configured() {
		panic(jimu.ErrComponentConfigured)
	}
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

// Configure process options and construct router.
func (r *Router) Configure() error {

	if r.configured() {
		panic(jimu.ErrComponentConfigured)
	}

	for _, op := range r.options {
		if err := op(r); err != nil {
			return err
		}
	}

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

	if !r.configured() {
		panic(jimu.ErrComponentNotConfigured)
	}

	// Match against path.
	data, params, found := r.router.Lookup(req.URL.EscapedPath())
	if !found {
		r.fallbackHandler(w, req, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}

	// Match against method.
	handler, found2 := data.(map[string]http.Handler)[req.Method]
	if !found2 {
		r.fallbackHandler(w, req, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	// Unescape path params.
	if err := unescapeParams(params); err != nil {
		r.fallbackHandler(w, req, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
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

func (r *FallbackRouter) configured() bool {
	return r.router != nil
}

// Handler add a FallbackHandler to the router.
func (r *FallbackRouter) Handler(path string, handler jimu.FallbackHandler) {
	if r.configured() {
		panic(jimu.ErrComponentConfigured)
	}
	r.handlerEntires[path] = handler
}

// Configure construct router.
func (r *FallbackRouter) Configure() error {

	if r.configured() {
		panic(jimu.ErrComponentConfigured)
	}
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

	if !r.configured() {
		panic(jimu.ErrComponentNotConfigured)
	}

	// Route the fallback handler.
	var h jimu.FallbackHandler = jimu.DefaultFallbackHandler
	data, params, found := r.router.Lookup(req.URL.EscapedPath())
	if found {
		h = data.(jimu.FallbackHandler)
	}

	// Unescape params.
	if err := unescapeParams(params); err != nil {
		h(w, req, "", http.StatusBadRequest)
		return
	}
	req = req.WithContext(context.WithValue(req.Context(), paramsCtxKey, params))

	// Run the fallbac handler.
	h(w, req, msg, status)
	return
}

var (
	paramRe         = regexp.MustCompile(`[:\*][a-zA-Z][a-zA-Z_0-9]*`)
	BadPathPattern  = fmt.Errorf("Bad path pattern")
	NotEnoughParams = fmt.Errorf("Not enough params to substitute")
	TooManyparams   = fmt.Errorf("Too many params to substitute")
)

type Path struct {
	path string

	// i == 0: for wildcard, e.g. "*location"
	// i > 0: for nonParams, e.g. "/do/"
	// i < 0: for params, e.g. ":action"
	partIndices  []int
	nonParams    []string
	paramNames   []string
	wildcardName string
}

// NewPath creates a Path.
func NewPath(path string) (*Path, error) {

	ret := &Path{
		path:        path,
		partIndices: []int{},
		nonParams:   []string{},
		paramNames:  []string{},
	}

	i := 0
	for _, loc := range paramRe.FindAllStringIndex(path, -1) {

		// Store non param part.
		nonParam := path[i:loc[0]]
		if len(nonParam) != 0 {
			ret.nonParams = append(ret.nonParams, nonParam)
			ret.partIndices = append(ret.partIndices, len(ret.nonParams))
		}

		// Store param part.
		name := path[loc[0]+1 : loc[1]]
		switch path[loc[0]] {
		case ':':
			ret.paramNames = append(ret.paramNames, name)
			ret.partIndices = append(ret.partIndices, -len(ret.paramNames))
		case '*':
			ret.wildcardName = name
			ret.partIndices = append(ret.partIndices, 0)
		default:
			panic(fmt.Errorf("Neither '*' or ':'?"))
		}

		// Move i
		i = loc[1]

	}

	// Store the remain non param part.
	nonParam := path[i:]
	if len(nonParam) != 0 {
		if ret.wildcardName != "" {
			return nil, fmt.Errorf("Wildcard '*param' should be the last part of path")
		}
		ret.nonParams = append(ret.nonParams, nonParam)
		ret.partIndices = append(ret.partIndices, len(ret.nonParams))
	}

	return ret, nil

}

// MustPath creates a path or panic if there is error.
func MustPath(path string) *Path {
	p, err := NewPath(path)
	if err != nil {
		panic(err)
	}
	return p
}

// String implement Stringer interface. Return the path pattern.
func (p *Path) String() string {
	return p.path
}

// Build concrete path from params. Param can be string, denco.Param or any fmt.Sprint-able object.
func (p *Path) Build(params ...interface{}) (string, error) {

	n := len(p.paramNames)
	if p.wildcardName != "" {
		n += 1
	}

	if len(params) < n {
		return "", NotEnoughParams
	} else if len(params) > n {
		return "", TooManyparams
	}

	parts := make([]string, len(p.partIndices))
	i := 0
	wildcard := ""
	for j, idx := range p.partIndices {

		// Non param part.
		if idx > 0 {
			parts[j] = p.nonParams[idx-1]
			continue
		}

		// Param part.
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

		// ':' case.
		if idx < 0 {
			parts[j] = url.PathEscape(s)
			continue
		}

		// '*' case.
		wildcard = s

	}

	// wildcard is the rest of path. Should be clean and join.
	if wildcard != "" {
		// Add "/" and clean to make sure wildcard does not escape to upper level.
		wildcard = path.Clean("/" + wildcard)
		wildcardParts := strings.Split(wildcard, "/")
		for k := 0; k < len(wildcardParts); k++ {
			wildcardParts[k] = url.PathEscape(wildcardParts[k])
		}
		wildcard = path.Join(wildcardParts...)
	}

	return path.Join(strings.Join(parts, ""), wildcard), nil

}

// Build a full url.
func (p *Path) BuildURL(baseURL *url.URL, params ...interface{}) (string, error) {
	pp, err := p.Build(params...)
	if err != nil {
		return "", err
	}
	cpyURL := *baseURL
	cpyURL.Path = path.Join(cpyURL.Path, pp)
	return cpyURL.String(), nil
}
