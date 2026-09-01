package web

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

const (
	sessionCookie  = "tsv_vpn_session"
	defaultSession = 12 * time.Hour

	// Lock out clients that fail repeatedly so bcrypt can't be ground
	// through a password list.
	maxLoginFailures = 5
	loginWindow      = time.Minute
	loginLockout     = time.Minute
)

var errBadPassword = errors.New("incorrect password")

// Sessions live in memory; a restart signs everyone out.
type Sessions struct {
	Credentials *Credentials
	TTL         time.Duration

	mu     sync.Mutex
	tokens map[string]time.Time

	throttleMu sync.Mutex
	attempts   map[string]*loginAttempts
}

type loginAttempts struct {
	failures    int
	windowEnds  time.Time
	lockedUntil time.Time
}

func NewSessions(credentials *Credentials) *Sessions {
	return &Sessions{
		Credentials: credentials,
		tokens:      map[string]time.Time{},
		attempts:    map[string]*loginAttempts{},
	}
}

func (s *Sessions) loginAllowed(ip string) (time.Duration, bool) {
	s.throttleMu.Lock()
	defer s.throttleMu.Unlock()
	s.pruneAttempts()
	if rec := s.attempts[ip]; rec != nil {
		if wait := time.Until(rec.lockedUntil); wait > 0 {
			return wait, false
		}
	}
	return 0, true
}

func (s *Sessions) loginFailed(ip string) {
	now := time.Now()
	s.throttleMu.Lock()
	defer s.throttleMu.Unlock()
	rec := s.attempts[ip]
	if rec == nil {
		rec = &loginAttempts{}
		s.attempts[ip] = rec
	}
	if now.After(rec.windowEnds) {
		rec.failures = 0
		rec.windowEnds = now.Add(loginWindow)
	}
	rec.failures++
	if rec.failures >= maxLoginFailures {
		rec.lockedUntil = now.Add(loginLockout)
		rec.failures = 0
	}
}

func (s *Sessions) loginSucceeded(ip string) {
	s.throttleMu.Lock()
	defer s.throttleMu.Unlock()
	delete(s.attempts, ip)
}

func (s *Sessions) pruneAttempts() {
	now := time.Now()
	for ip, rec := range s.attempts {
		if now.After(rec.windowEnds) && now.After(rec.lockedUntil) {
			delete(s.attempts, ip)
		}
	}
}

func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func (s *Sessions) Login(password string) (string, error) {
	if !s.Credentials.Matches(password) {
		return "", errBadPassword
	}
	return s.grant()
}

func (s *Sessions) grant() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.expire()
	s.tokens[token] = time.Now().Add(s.ttl())
	return token, nil
}

func (s *Sessions) Valid(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	expiry, ok := s.tokens[token]
	return ok && time.Now().Before(expiry)
}

func (s *Sessions) Logout(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, token)
}

func (s *Sessions) RevokeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens = map[string]time.Time{}
}

func (s *Sessions) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.Credentials.NeedsSetup() {
			redirectTo(w, r, "/setup")
			return
		}
		if !s.authenticated(r) {
			redirectTo(w, r, "/login")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// htmx follows redirects into the swap target, so it gets HX-Redirect instead.
func redirectTo(w http.ResponseWriter, r *http.Request, to string) {
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", to)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

func (s *Sessions) authenticated(r *http.Request) bool {
	cookie, err := r.Cookie(sessionCookie)
	return err == nil && s.Valid(cookie.Value)
}

func (s *Sessions) expire() {
	now := time.Now()
	for token, expiry := range s.tokens {
		if now.After(expiry) {
			delete(s.tokens, token)
		}
	}
}

func (s *Sessions) ttl() time.Duration {
	if s.TTL > 0 {
		return s.TTL
	}
	return defaultSession
}

type loginData struct {
	Error string
}

func (s *Server) showLogin(w http.ResponseWriter, r *http.Request) {
	if s.Sessions.Credentials.NeedsSetup() {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	if s.Sessions.authenticated(r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.render(w, r, "login", "Sign in", loginData{})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if wait, ok := s.Sessions.loginAllowed(ip); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		w.WriteHeader(http.StatusTooManyRequests)
		s.render(w, r, "login", "Sign in", loginData{Error: "Too many attempts. Wait a minute and try again."})
		return
	}
	token, err := s.Sessions.Login(r.FormValue("password"))
	if err != nil {
		s.Sessions.loginFailed(ip)
		w.WriteHeader(http.StatusUnauthorized)
		s.render(w, r, "login", "Sign in", loginData{Error: "Incorrect password."})
		return
	}
	s.Sessions.loginSucceeded(ip)
	s.setSession(w, r, token)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) setSession(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(s.Sessions.ttl().Seconds()),
	})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		s.Sessions.Logout(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
