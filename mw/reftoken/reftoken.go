package reftoken

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/huangjunwen/jimu"
	"net/http"
	"net/textproto"
	"regexp"
	"strconv"
)

const (
	DefaultTokenLength = 32
	DefaultTTL         = 3600 * 3
	// These are some default internal header names.
	DefaultTTLHeaderName    = "Reftoken-TTL"
	DefaultLogoutHeaderName = "Reftoken-Logout"
)

// Option is the option to to create RefTokenManager.
type Option func(*RefTokenManager) error

// Store set the kv store to use in RefTokenManager (required).
func Store(storeURL string) Option {
	return func(m *RefTokenManager) error {
		store, err := NewKVStore(storeURL)
		if err != nil {
			return err
		}
		m.store = store
		return nil
	}
}

// LoggerGetter set the logger getter for RefTokenManager (required).
func LoggerGetter(loggerGetter jimu.LoggerGetter) Option {
	return func(m *RefTokenManager) error {
		if loggerGetter == nil {
			return fmt.Errorf("LoggerGetter is nil")
		}
		m.loggerGetter = loggerGetter
		return nil
	}
}

// TokenLength set the ref token's length (before base64 encode).
func TokenLength(l int) Option {
	return func(m *RefTokenManager) error {
		if l < 20 {
			return fmt.Errorf("TokenLength: %d is too short", l)
		}
		m.tokenLength = l
		return nil
	}
}

// TTL set the default ttl (in seconds) for kv in store.
func TTL(ttl int) Option {
	return func(m *RefTokenManager) error {
		if ttl <= 0 {
			return fmt.Errorf("TTL: should > 0 but got %d", ttl)
		}
		m.ttl = ttl
		return nil
	}
}

// TTLHeaderName set the response header name to specify ttl for kv.
func TTLHeaderName(headerName string) Option {
	return func(m *RefTokenManager) error {
		headerName, err := checkHeaderName(headerName)
		if err != nil {
			return err
		}
		m.ttlHeaderName = headerName
		return nil
	}
}

// LogoutHeaderName set the response header name to remove kv.
func LogoutHeaderName(headerName string) Option {
	return func(m *RefTokenManager) error {
		headerName, err := checkHeaderName(headerName)
		if err != nil {
			return err
		}
		m.logoutHeaderName = headerName
		return nil
	}
}

// Real2RefRule add a rule specifying how to map a (internal) real token to a
// (external) ref token. (required at least one)
func Real2RefRule(realTokenHeaderName string, refTokenSetter RefTokenSetter) Option {
	return func(m *RefTokenManager) error {
		realTokenHeaderName, err := checkHeaderName(realTokenHeaderName)
		if err != nil {
			return err
		}
		if refTokenSetter == nil {
			return fmt.Errorf("RefTokenSetter is nil")
		}
		m.real2RefRules = append(m.real2RefRules, real2RefRule{
			realTokenHeaderName: realTokenHeaderName,
			refTokenSetter:      refTokenSetter,
		})
		return nil
	}
}

// Ref2RealRule add a rule specifying how to map a (external) ref token (external) to a
// (internal) real token. (required at least one)
func Ref2RealRule(refTokenGetter RefTokenGetter, realTokenHeaderName string) Option {
	return func(m *RefTokenManager) error {
		if refTokenGetter == nil {
			return fmt.Errorf("RefTokenGetter is nil")
		}
		realTokenHeaderName, err := checkHeaderName(realTokenHeaderName)
		if err != nil {
			return err
		}
		m.ref2RealRules = append(m.ref2RealRules, ref2RealRule{
			realTokenHeaderName: realTokenHeaderName,
			refTokenGetter:      refTokenGetter,
		})
		return nil
	}
}

// DefaultRules add some default rules for convenient:
//    (external) "Reftoken-Ref-Token"        -> (internal) "Reftoken-Real-Token"
//    (external) cookie "reftoken"           -> (internal) "Reftoken-Real-Token"
//    (internal) "Reftoken-Set"              -> (external) "Reftoken-Ref-Token"
//    (internal) "Reftoken-Set-Cookie"       -> (external) cookie "reftoken"
// Thus no matter whether the reftoken is come from web page request (in cookie) or
// api request (in header), handlers can use "Reftoken-Real-Token" to get authentication
// information.
func DefaultRules() Option {
	return func(m *RefTokenManager) error {

		ops := []Option{
			Real2RefRule("Reftoken-Set", MustGenericSetter("Reftoken-Ref-Token")),
			Real2RefRule("Reftoken-Set-Cookie", MustCookieSetter(
				&http.Cookie{
					Name:     "reftoken",
					Path:     "/",
					HttpOnly: true,
				},
			)),
			Ref2RealRule(MustGenericGetter("Reftoken-Ref-Token"), "Reftoken-Real-Token"),
			Ref2RealRule(MustCookieGetter("reftoken"), "Reftoken-Real-Token"),
		}
		for _, op := range ops {
			if err := op(m); err != nil {
				return err
			}
		}
		return nil

	}
}

// RefTokenManager stores information to translate between external ref tokens
// and internal real tokens. See: https://www.slideshare.net/opencredo/authentication-in-microservice-systems-david-borsos
type RefTokenManager struct {
	// stores refToken -> realToken mapping with ttl.
	store KVStore

	// Translate rules.
	real2RefRules []real2RefRule
	ref2RealRules []ref2RealRule

	// Logger getter.
	loggerGetter jimu.LoggerGetter

	// Default ttl in seconds when storing data.
	ttl int

	// Length of ref token (in bytes before base64 encode)
	tokenLength int

	// Special header names.
	ttlHeaderName    string
	logoutHeaderName string
}

// New create RefTokenManager.
func New(options ...Option) (*RefTokenManager, error) {

	ret := &RefTokenManager{}
	ops := []Option{
		TokenLength(DefaultTokenLength),
		TTL(DefaultTTL),
		TTLHeaderName(DefaultTTLHeaderName),
		LogoutHeaderName(DefaultLogoutHeaderName),
	}
	ops = append(ops, options...)
	for _, op := range ops {
		if err := op(ret); err != nil {
			return nil, err
		}
	}

	if ret.store == nil {
		return nil, fmt.Errorf("No Store in RefTokenManager")
	}
	if ret.loggerGetter == nil {
		return nil, fmt.Errorf("No LoggerGetter in RefTokenManager")
	}
	if len(ret.ref2RealRules) == 0 {
		return nil, fmt.Errorf("No Ref2RealRule in RefTokenManager")
	}
	if len(ret.real2RefRules) == 0 {
		return nil, fmt.Errorf("No Real2RefRule in RefTokenManager")
	}
	return ret, nil

}

// Wrap is the middleware.
func (m *RefTokenManager) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.serve(w, r, next)
	})
}

func (m *RefTokenManager) serve(w http.ResponseWriter, r *http.Request, next http.Handler) {

	lg := m.loggerGetter(r.Context())

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
		lg.Log(
			"level", "debug",
			"src", "reftoken",
			"message", fmt.Sprintf("store.Get(%v)", refTokens),
		)

		realTokens, err := m.store.Get(refTokens)
		if err != nil {
			lg.Log(
				"level", "error",
				"src", "reftoken",
				"error", fmt.Errorf("store.Get(%v): %s", refTokens, err),
			)
			return nil
		}

		lg.Log(
			"level", "debug",
			"src", "reftoken",
			"message", fmt.Sprintf("store.Get(...) => %v", realTokens),
		)

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

		lg.Log(
			"level", "debug",
			"src", "reftoken",
			"message", fmt.Sprintf("store.Del(%v)", existRefTokens),
		)

		if err := m.store.Del(existRefTokens); err != nil {
			lg.Log(
				"level", "error",
				"src", "reftoken",
				"error", fmt.Errorf("store.Del(%v): %s", existRefTokens, err),
			)
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

		lg.Log(
			"level", "debug",
			"src", "reftoken",
			"message", fmt.Sprintf("store.set(%v, %d)", kvs, ttl),
		)

		if err := m.store.Set(kvs, ttl); err != nil {
			lg.Log(
				"level", "error",
				"src", "reftoken",
				"error", err,
			)
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

func (m *RefTokenManager) generateRefToken(_ string) string {

	buf := make([]byte, m.tokenLength)
	_, err := rand.Read(buf)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(buf)

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
