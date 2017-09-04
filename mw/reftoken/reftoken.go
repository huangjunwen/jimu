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

// NewManager creates a new reftoken manager.
func NewManager(store KVStore, next http.Handler) *Manager {

	return &Manager{
		store:            store,
		ttl:              DefaultTTL,
		ttlHeaderName:    DefaultTTLHeaderName,
		logoutHeaderName: DefaultLogoutHeaderName,
		next:             next,
	}
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

// ServeHTTP implement http.Handler interface.
func (m *Manager) ServeHTTP(w http.ResponseWriter, r *http.Request) {

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
		realTokens, err := m.store.Get(refTokens)
		if err != nil {
			lg.Error().Err(fmt.Errorf("KVStore.Get: %s", err)).Str("src", "reftoken").Msg("")
			return nil
		}

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

		// If any.
		if len(refTokens) != 0 {

			if err := m.store.Set(kvs, ttl); err != nil {

				lg.Error().Err(fmt.Errorf("KVStore.Set: %s", err)).Str("src", "reftoken").Msg("")

			} else {

				for i, refToken := range refTokens {
					refTokenSetters[i](h, refToken)
				}

			}

		}

	}

	m.next.ServeHTTP(&responseWriterProxy{
		ResponseWriter: w,
		headerModifier: applyRulesToResponseHeader,
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
func NewCookieRefTokenSetter(baseCookie *http.Cookie) (RefTokenSetter, error) {

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

// NewGenericRefTokenSetter creates a RefTokenSetter storing token in header directly.
func NewGenericRefTokenSetter(headerName string) (RefTokenSetter, error) {

	headerName, err := checkHeaderName(headerName)
	if err != nil {
		return nil, err
	}
	return func(header http.Header, refToken string) {
		// HeaderName is already canonical.
		header[headerName] = []string{refToken}
	}, nil

}

// NewCookieRefTokenGetter creates a RefTokenGetter retriving token from cookie.
func NewCookieRefTokenGetter(cookieName string) (RefTokenGetter, error) {

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

// NewGenericRefTokenGetter creates a RefTokenGetter retriving token from header.
func NewGenericRefTokenGetter(headerName string) (RefTokenGetter, error) {

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
