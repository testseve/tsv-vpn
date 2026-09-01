package web

import (
	"net/http"

	tsvvpn "tsv-vpn"
	"tsv-vpn/internal/changelog"
)

func (s *Server) releases(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "releases", "Release notes", changelog.Parse(tsvvpn.Changelog))
}
