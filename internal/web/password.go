package web

import "net/http"

type passwordData struct {
	Pinned bool
	Error  string
	Done   bool
}

func (s *Server) showPassword(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "password", "Password", passwordData{Pinned: s.pinned()})
}

// Changing the password drops every other session: someone else might know
// the old one.
func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	if s.pinned() {
		s.passwordError(w, r, "The admin password comes from ADMIN_PASSWORD_HASH. Change it there.")
		return
	}
	// The current-password check is an oracle like /login; same throttle.
	ip := clientIP(r)
	if _, ok := s.Sessions.loginAllowed(ip); !ok {
		s.passwordError(w, r, "Too many attempts. Wait a minute and try again.")
		return
	}
	if !s.Sessions.Credentials.Matches(r.FormValue("current")) {
		s.Sessions.loginFailed(ip)
		s.passwordError(w, r, "That is not the current password.")
		return
	}
	s.Sessions.loginSucceeded(ip)

	password := r.FormValue("password")
	if password != r.FormValue("confirm") {
		s.passwordError(w, r, "Those passwords do not match.")
		return
	}
	if err := s.Sessions.Credentials.Set(password); err != nil {
		s.passwordError(w, r, err.Error())
		return
	}

	s.Sessions.RevokeAll()
	token, err := s.Sessions.grant()
	if err != nil {
		s.fail(w, err)
		return
	}
	s.setSession(w, r, token)
	s.render(w, r, "password", "Password", passwordData{Done: true})
}

func (s *Server) pinned() bool {
	return len(s.Sessions.Credentials.EnvHash) > 0
}

func (s *Server) passwordError(w http.ResponseWriter, r *http.Request, message string) {
	w.WriteHeader(http.StatusUnprocessableEntity)
	s.render(w, r, "password", "Password", passwordData{Pinned: s.pinned(), Error: message})
}
