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

	// Wrapped handler.
	next http.Handler
}

// New creates a new reftoken manager.
func New(store KVStore, next http.Handler) *Manager {

	return &Manager{
		store:            store,
		ttl:              DefaultTTL,
		ttlHeaderName:    DefaultTTLHeaderName,
		logoutHeaderName: DefaultLogoutHeaderName,
		next:             next,
	}
}

// SetTTL set default ttl for kv.
func (m *Manager) SetTTL(ttl int) {
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

// ServeHTTP implement http.Handler interface.
func (m *Manager) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	lg := logger.Logger(r)

	// handleRequest translate ref tokens to real tokens and return ref tokens.
	handleRequest := func() []string {

		refTokens := []string{}
		realTokenHeaderNames := []string{}

		for _, rule := range m.ref2RealRules {

			// !!! Make sure real token header name is NOT present in request to
			// avoid fake ones.
			realTokenHeaderName := rule.realTokenHeaderName
			delete(r.Header, realTokenHeaderName)

			// Try to extract ref token.
			refToken := rule.refTokenGetter(r)
			if refToken == "" {
				continue
			}

			realTokenHeaderNames = append(realTokenHeaderNames, realTokenHeaderName)
			refTokens = append(refTokens, refToken)
		}

		// Translate to real tokens and set to request header.
		if len(realTokenHeaderNames) != 0 {
			realTokens, err := m.store.Get(refTokens)
			if err == nil {
				for i, realTokenHeaderName := range realTokenHeaderNames {
					r.Header[realTokenHeaderName] = []string{realTokens[i]}
				}
			} else {
				lg.Error().Err(err).Str("src", "reftoken:get").Msg("")
			}
		}

		return refTokens

	}

	currentRefTokens := handleRequest()

	handleLogout := func(h http.Header) {

		if _, ok := h[m.logoutHeaderName]; !ok {
			return
		}
		delete(h, m.logoutHeaderName)

		// Logout all at once.
		if err := m.store.Del(currentRefTokens); err != nil {
			lg.Error().Err(err).Str("src", "reftoken:del").Msg("")
		}

	}

	handleResponseHeader := func(h http.Header) {

		// Handle logout logic.
		handleLogout(h)

		// Determin ttl.
		ttl := m.ttl
		v := h[m.ttlHeaderName]
		if len(v) != 0 {
			ttl, _ = strconv.Atoi(v[0])
		}

		// Handler real tokens.
		refTokenSetters := []RefTokenSetter{}
		refTokens := []string{}
		kvs := []KV{}

		for _, rule := range m.real2RefRules {

			// Extract real token.
			realTokenHeaderName := rule.realTokenHeaderName
			realToken := ""
			v := h[realTokenHeaderName]
			if len(v) != 0 {
				realToken = v[0]
			}

			// !!! Make sure real token headers are NOT present in response
			// to avoid sensitive information leaking.
			delete(h, realTokenHeaderName)

			// Ignore empty real token.
			if realToken == "" {
				continue
			}

			// Generate ref token for the real token.
			refToken := m.generateRefToken(realToken)

			// Push to array for later batch operation.
			refTokenSetters = append(refTokenSetters, rule.refTokenSetter)
			refTokens = append(refTokens, refToken)
			kvs = append(kvs, KV{Key: refToken, Value: realToken})

		}

		if len(kvs) != 0 {
			if err := m.store.Set(kvs, ttl); err == nil {
				for i, refToken := range refTokens {
					refTokenSetters[i](h, refToken)
				}
			} else {
				logger.Logger(r).Error().Err(err).Str("src", "reftoken").Msg("")
			}
		}

	}

	m.next.ServeHTTP(&responseWriterProxy{
		ResponseWriter: w,
		headerModifier: handleResponseHeader,
	}, r)

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

// NewCookieRefTokenSetter creates a RefTokenSetter storing token in cookie.
func NewCookieRefTokenSetter(baseCookie *http.Cookie) RefTokenSetter {

	if err := checkCookieName(baseCookie.Name); err != nil {
		panic(err)
	}
	return func(header http.Header, refToken string) {
		cookie := *baseCookie
		cookie.Value = refToken
		v := cookie.String()
		if v != "" {
			header.Add("Set-Cookie", v)
		}
	}

}

// NewGenericRefTokenSetter creates a RefTokenSetter storing token in header directly.
func NewGenericRefTokenSetter(headerName string) RefTokenSetter {

	headerName, err := checkHeaderName(headerName)
	if err != nil {
		panic(err)
	}
	return func(header http.Header, refToken string) {
		// HeaderName is already canonical.
		header[headerName] = []string{refToken}
	}

}

// NewCookieRefTokenGetter creates a RefTokenGetter retriving token from cookie.
func NewCookieRefTokenGetter(cookieName string) RefTokenGetter {

	if err := checkCookieName(cookieName); err != nil {
		panic(err)
	}
	return func(r *http.Request) string {
		cookie, err := r.Cookie(cookieName)
		if err != nil {
			return ""
		}
		return cookie.Value
	}

}

// NewGenericRefTokenGetter creates a RefTokenGetter retriving token from header.
func NewGenericRefTokenGetter(headerName string) RefTokenGetter {

	headerName, err := checkHeaderName(headerName)
	if err != nil {
		panic(err)
	}
	return func(r *http.Request) string {
		// headerName is already canonical.
		v := r.Header[headerName]
		if len(v) == 0 {
			return ""
		}
		return v[0]
	}

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
