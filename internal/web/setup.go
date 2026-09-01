package web

import "net/http"

type setupData struct {
	Error string
}

func (s *Server) showSetup(w http.ResponseWriter, r *http.Request) {
	if !s.Sessions.Credentials.NeedsSetup() {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.render(w, r, "setup", "Choose a password", setupData{})
}

// First request to set a password wins; the page is gone from then on.
func (s *Server) setup(w http.ResponseWriter, r *http.Request) {
	if !s.Sessions.Credentials.NeedsSetup() {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	password := r.FormValue("password")
	if password != r.FormValue("confirm") {
		s.setupError(w, r, "Those passwords do not match.")
		return
	}
	if err := s.Sessions.Credentials.Set(password); err != nil {
		s.setupError(w, r, err.Error())
		return
	}

	token, err := s.Sessions.grant()
	if err != nil {
		s.fail(w, err)
		return
	}
	s.setSession(w, r, token)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) setupError(w http.ResponseWriter, r *http.Request, message string) {
	w.WriteHeader(http.StatusUnprocessableEntity)
	s.render(w, r, "setup", "Choose a password", setupData{Error: message})
}
