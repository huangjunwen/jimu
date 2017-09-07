package router

import (
	"context"
	"github.com/huangjunwen/MW/mw/fallback"
	"github.com/julienschmidt/httprouter"
	"net/http"
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
func (r *Router) Handler(method, path string, h http.Handler) {
	r.Router.Handle(method, path, func(w http.ResponseWriter, req *http.Request, params httprouter.Params) {
		h.ServeHTTP(w, req.WithContext(context.WithValue(req.Context(), paramsCtxKey, params)))
	})
}

// HandlerFunc regist http.HandlerFunc to the router.
func (r *Router) HandlerFunc(method, path string, h http.HandlerFunc) {
	r.Handler(method, path, h)
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
