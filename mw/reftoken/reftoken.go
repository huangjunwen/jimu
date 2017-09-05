package reftoken

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/huangjunwen/MW/mw/logger"
	"net/http"
	"net/textproto"
	"regexp"
	"strconv"
)

const (
	DefaultTTL = 3600 * 3
	// These are some default internal header names.
	DefaultTTLHeaderName    = "Reftoken-TTL"
	DefaultLogoutHeaderName = "Reftoken-Logout"
)

// Manager stores information to translate between external ref tokens
// and internal real tokens. See: https://www.slideshare.net/opencredo/authentication-in-microservice-systems-david-borsos
type Manager struct {
	// stores refToken -> realToken mapping with ttl.
	store KVStore

	// Default ttl in seconds when storing data.
	ttl int

	// Special header names.
	ttlHeaderName    string
	logoutHeaderName string

	// Translate rules.
	real2RefRules []real2RefRule
	ref2RealRules []ref2RealRule
}

// NewManager creates a new reftoken manager.
func NewManager(storeURL string) (*Manager, error) {

	store, err := NewKVStore(storeURL)
	if err != nil {
		return nil, err
	}

	return &Manager{
		store:            store,
		ttl:              DefaultTTL,
		ttlHeaderName:    DefaultTTLHeaderName,
		logoutHeaderName: DefaultLogoutHeaderName,
	}, nil
}

// SetTokenTTL set default ttl for tokens.
func (m *Manager) SetTokenTTL(ttl int) {
	if ttl > 0 {
		m.ttl = ttl
	}
}

func (m *Manager) generateRefToken(_ string) string {

	buf := make([]byte, 20)
	_, err := rand.Read(buf)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(buf)

}

func (m *Manager) serve(w http.ResponseWriter, r *http.Request, next http.Handler) {

	lg := logger.Logger(r)

	// Apply ref 2 real token rules. Return ref tokens.
	applyRulesToRequest := func() []string {

		realTokenHeaderNames := []string{}
		refTokens := []string{}

		for _, rule := range m.ref2RealRules {

			// Extract ref token from request.
			realTokenHeaderName := rule.realTokenHeaderName
			refToken := rule.refTokenGetter(r)

			// !!! Ensure there is no header name using realTokenHeaderName
			// to avoid fake ones.
			delete(r.Header, realTokenHeaderName)

			// Ignore empty.
			if refToken == "" {
				continue
			}

			// Append to array for later batch process.
			realTokenHeaderNames = append(realTokenHeaderNames, realTokenHeaderName)
			refTokens = append(refTokens, refToken)

		}

		// Ref token not found.
		if len(refTokens) == 0 {
			return nil
		}

		// Translate ref tokens to real tokens.
		lg.Debug().Strs("get:refTokens", refTokens).Str("src", "reftoken").Msg("")
		realTokens, err := m.store.Get(refTokens)
		if err != nil {
			lg.Error().Err(fmt.Errorf("KVStore.Get: %s", err)).Str("src", "reftoken").Msg("")
			return nil
		}
		lg.Debug().Strs("got:realTokens", realTokens).Str("src", "reftoken").Msg("")

		// Should never happen.
		if len(realTokens) != len(realTokenHeaderNames) {
			panic(fmt.Errorf("len(realTokens)(%d) != len(realTokenHeaderNames)(%d)",
				len(realTokens), len(realTokenHeaderNames)))
		}

		// Set real tokens to header.
		existRefTokens := []string{}
		for i, realToken := range realTokens {
			// Ignore empty.
			if realToken == "" {
				continue
			}
			r.Header[realTokenHeaderNames[i]] = []string{realToken}
			existRefTokens = append(existRefTokens, refTokens[i])
		}

		return existRefTokens

	}

	existRefTokens := applyRulesToRequest()

	handleLogout := func(h http.Header) {
		if _, ok := h[m.logoutHeaderName]; !ok {
			return
		}
		delete(h, m.logoutHeaderName)
		lg.Debug().Strs("del:refTokens", existRefTokens).Str("src", "reftoken").Msg("")
		if err := m.store.Del(existRefTokens); err != nil {
			lg.Error().Err(fmt.Errorf("KVStore.Del: %s", err)).Str("src", "reftoken").Msg("")
		}
	}

	applyRulesToResponseHeader := func(h http.Header) {

		handleLogout(h)

		// Since headers here are already canonical, no need to
		// call h.Get()
		getHeader := func(headerName string) string {
			v := h[headerName]
			if len(v) == 0 {
				return ""
			}
			return v[0]
		}

		// Determin ttl.
		ttl, _ := strconv.Atoi(getHeader(m.ttlHeaderName))
		if ttl <= 0 {
			ttl = m.ttl
		}

		refTokenSetters := []RefTokenSetter{}
		refTokens := []string{}
		kvs := map[string]string{}

		for _, rule := range m.real2RefRules {

			// Extract real token from response header.
			realTokenHeaderName := rule.realTokenHeaderName
			realToken := getHeader(realTokenHeaderName)

			// !!! Ensure there is no realTokenHeaderName in header
			// to avoid information leak.
			delete(h, realTokenHeaderName)

			// Ignore empty.
			if realToken == "" {
				continue
			}

			// Generate ref token -> real token.
			refToken := m.generateRefToken(realToken)

			// Append to array for later batch process.
			refTokenSetters = append(refTokenSetters, rule.refTokenSetter)
			refTokens = append(refTokens, refToken)
			kvs[refToken] = realToken

		}

		if len(refTokens) == 0 {
			return
		}

		lg.Debug().Interface("set:kvs", kvs).Int("ttl", ttl).Str("src", "reftoken").Msg("")
		if err := m.store.Set(kvs, ttl); err != nil {
			lg.Error().Err(fmt.Errorf("KVStore.Set: %s", err)).Str("src", "reftoken").Msg("")
			return
		}

		for i, refToken := range refTokens {
			refTokenSetters[i](h, refToken)
		}

	}

	next.ServeHTTP(&responseWriterProxy{
		ResponseWriter: w,
		headerModifier: applyRulesToResponseHeader,
	}, r)

}

// Wrap is the middleware function.
func (m *Manager) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.serve(w, r, next)
	})
}

// AddRef2RealRule add a translate rule to translate ref token to real token.
func (m *Manager) AddRef2RealRule(refTokenGetter RefTokenGetter, realTokenHeaderName string) (err error) {

	realTokenHeaderName, err = checkHeaderName(realTokenHeaderName)
	if err != nil {
		return
	}
	m.ref2RealRules = append(m.ref2RealRules, ref2RealRule{
		realTokenHeaderName: realTokenHeaderName,
		refTokenGetter:      refTokenGetter,
	})
	return

}

// AddReal2RefRule add a translate rule to translate real token to ref token.
func (m *Manager) AddReal2RefRule(realTokenHeaderName string, refTokenSetter RefTokenSetter) (err error) {

	realTokenHeaderName, err = checkHeaderName(realTokenHeaderName)
	if err != nil {
		return
	}
	m.real2RefRules = append(m.real2RefRules, real2RefRule{
		realTokenHeaderName: realTokenHeaderName,
		refTokenSetter:      refTokenSetter,
	})
	return

}

// AddDefaultRules add some default rules for convenient use:
//    (external) "Reftoken-Ref-Token"        -> (internal) "Reftoken-Real-Token"
//    (external) cookie "reftoken"           -> (internal) "Reftoken-Real-Token"
//    (internal) "Reftoken-Set"              -> (external) "Reftoken-Ref-Token"
//    (internal) "Reftoken-Set-Cookie"       -> (external) cookie "reftoken"
// Thus no matter whether the reftoken is come from web page request (in cookie) or
// api request (in header), handlers can use "Reftoken-Real-Token" to get authentication
// information.
func (m *Manager) AddDefaultRules() {

	must := func(err error) {
		if err != nil {
			panic(err)
		}
	}

	must(m.AddReal2RefRule("Reftoken-Set", MustGenericSetter("Reftoken-Ref-Token")))
	must(m.AddReal2RefRule("Reftoken-Set-Cookie", MustCookieSetter(
		&http.Cookie{
			Name:     "reftoken",
			Path:     "/",
			HttpOnly: true,
		},
	)))
	must(m.AddRef2RealRule(MustGenericGetter("Reftoken-Ref-Token"), "Reftoken-Real-Token"))
	must(m.AddRef2RealRule(MustCookieGetter("reftoken"), "Reftoken-Real-Token"))

}

type responseWriterProxy struct {
	http.ResponseWriter
	headerWrote    bool
	headerModifier func(http.Header)
}

// WriteHeader implement http.ResponseWriter interface.
func (rw *responseWriterProxy) WriteHeader(status int) {

	if rw.headerWrote {
		return
	}

	rw.headerWrote = true
	rw.headerModifier(rw.ResponseWriter.Header())
	rw.ResponseWriter.WriteHeader(status)

}

// Write implement http.ResponseWriter interface.
func (rw *responseWriterProxy) Write(content []byte) (int, error) {
	rw.WriteHeader(http.StatusOK)
	return rw.ResponseWriter.Write(content)
}

type real2RefRule struct {
	realTokenHeaderName string
	refTokenSetter      RefTokenSetter
}

type ref2RealRule struct {
	realTokenHeaderName string
	refTokenGetter      RefTokenGetter
}

// RefTokenSetter sets a refToken into response's header. refToken is guarantee
// to be safe to set to header.
type RefTokenSetter func(header http.Header, refToken string)

// RefTokenGetter gets refToken from request.
type RefTokenGetter func(r *http.Request) string

// NewCookieSetter creates a RefTokenSetter storing ref token in cookie.
func NewCookieSetter(baseCookie *http.Cookie) (RefTokenSetter, error) {

	if err := checkCookieName(baseCookie.Name); err != nil {
		return nil, err
	}
	return func(header http.Header, refToken string) {
		cookie := *baseCookie
		cookie.Value = refToken
		v := cookie.String()
		if v != "" {
			header.Add("Set-Cookie", v)
		}
	}, nil

}

// MustCookieSetter is the must version of NewCookieSetter.
func MustCookieSetter(baseCookie *http.Cookie) RefTokenSetter {
	ret, err := NewCookieSetter(baseCookie)
	if err != nil {
		panic(err)
	}
	return ret
}

// NewGenericSetter creates a RefTokenSetter storing ref token in header directly.
func NewGenericSetter(headerName string) (RefTokenSetter, error) {

	headerName, err := checkHeaderName(headerName)
	if err != nil {
		return nil, err
	}
	return func(header http.Header, refToken string) {
		// HeaderName is already canonical.
		header[headerName] = []string{refToken}
	}, nil

}

// MustGenericSetter is the must version of NewGenericSetter.
func MustGenericSetter(headerName string) RefTokenSetter {
	ret, err := NewGenericSetter(headerName)
	if err != nil {
		panic(err)
	}
	return ret
}

// NewCookieGetter creates a RefTokenGetter retriving ref token from cookie.
func NewCookieGetter(cookieName string) (RefTokenGetter, error) {

	if err := checkCookieName(cookieName); err != nil {
		return nil, err
	}
	return func(r *http.Request) string {
		cookie, err := r.Cookie(cookieName)
		if err != nil {
			return ""
		}
		return cookie.Value
	}, nil

}

// MustCookieGetter is the must version of NewCookieGetter.
func MustCookieGetter(cookieName string) RefTokenGetter {
	ret, err := NewCookieGetter(cookieName)
	if err != nil {
		panic(err)
	}
	return ret
}

// NewGenericGetter creates a RefTokenGetter retriving ref token from header.
func NewGenericGetter(headerName string) (RefTokenGetter, error) {

	headerName, err := checkHeaderName(headerName)
	if err != nil {
		return nil, err
	}
	return func(r *http.Request) string {
		// headerName is already canonical.
		v := r.Header[headerName]
		if len(v) == 0 {
			return ""
		}
		return v[0]
	}, nil

}

// MustGenericGetter is the must version of NewGenericGetter.
func MustGenericGetter(headerName string) RefTokenGetter {
	ret, err := NewGenericGetter(headerName)
	if err != nil {
		panic(err)
	}
	return ret
}

var (
	cookieNameRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]*$`)
	headerNameRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9\-]*$`)
)

func checkCookieName(name string) error {
	if name == "" {
		return fmt.Errorf("checkCookieName: empty cookie name.")
	}
	if !cookieNameRe.MatchString(name) {
		return fmt.Errorf("checkCookieName: bad cookie name %+q.", name)
	}
	return nil
}

func checkHeaderName(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("checkHeaderName: empty header name.")
	}
	if !headerNameRe.MatchString(name) {
		return "", fmt.Errorf("checkHeaderName: bad header name %+q.", name)
	}
	return textproto.CanonicalMIMEHeaderKey(name), nil
}
