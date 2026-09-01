package web

import (
	"context"
	"embed"
	"html/template"
	"log/slog"
	"net/http"
	"net/netip"
	"sync"
	"time"

	tsvvpn "tsv-vpn"
	"tsv-vpn/internal/db"
	"tsv-vpn/internal/discover"
	"tsv-vpn/internal/logbuf"
)

//go:embed templates static
var files embed.FS

var (
	pages     = parsePages("login", "setup", "password", "dashboard", "connection", "subnets", "tailnet", "releases")
	fragments = template.Must(template.ParseFS(files, "templates/partials/*.html"))
)

type Tunnels interface {
	Status(name string) (db.State, string)
	Nudge()
}

type Checks interface {
	Check(ctx context.Context, conn db.Connection)
	CheckSubnet(ctx context.Context, subnet db.LocalSubnet)
}

type GatewayTest interface {
	Test(ctx context.Context, host string) (discover.PreflightResult, error)
}

type Server struct {
	Store    *db.Store
	Tunnels  Tunnels
	Checks   Checks
	Gateway  GatewayTest
	Tailnet  Tailnet
	Scanner  Scanner
	Prober   Prober
	Hostname string

	scansOnce sync.Once
	running   *scans

	probeMu   sync.Mutex
	probedAt  time.Time
	probeHops []netip.Addr
	Logs      *logbuf.Ring
	Sessions  *Sessions
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.FileServerFS(files))
	mux.HandleFunc("GET /setup", s.showSetup)
	mux.HandleFunc("POST /setup", s.setup)
	mux.HandleFunc("GET /login", s.showLogin)
	mux.HandleFunc("POST /login", s.login)
	mux.HandleFunc("POST /logout", s.logout)

	private := http.NewServeMux()
	private.HandleFunc("GET /{$}", s.dashboard)
	private.HandleFunc("GET /connections/new", s.newConnection)
	private.HandleFunc("POST /connections", s.createConnection)
	private.HandleFunc("POST /connections/preflight", s.preflight)
	private.HandleFunc("GET /connections/{id}/edit", s.editConnection)
	private.HandleFunc("POST /connections/{id}", s.updateConnection)
	private.HandleFunc("GET /connections/{id}/status", s.connectionStatus)
	private.HandleFunc("POST /connections/{id}/enable", s.setEnabled(true))
	private.HandleFunc("POST /connections/{id}/disable", s.setEnabled(false))
	private.HandleFunc("POST /connections/{id}/check", s.checkConnection)
	private.HandleFunc("GET /connections/{id}/logs", s.connectionLogs)
	private.HandleFunc("GET /connections/{id}/logs/close", s.closeConnectionLogs)
	private.HandleFunc("DELETE /connections/{id}", s.deleteConnection)
	private.HandleFunc("GET /releases", s.releases)
	private.HandleFunc("GET /password", s.showPassword)
	private.HandleFunc("POST /password", s.changePassword)
	private.HandleFunc("GET /tailnet", s.tailnetPage)
	private.HandleFunc("GET /tailnet/status", s.tailnetStatus)
	private.HandleFunc("POST /tailnet/login", s.tailnetLogin)
	private.HandleFunc("POST /tailnet/exit-node", s.tailnetExitNode)
	private.HandleFunc("GET /subnets", s.subnets)
	private.HandleFunc("POST /subnets", s.addSubnet)
	private.HandleFunc("POST /subnets/{id}/enable", s.setSubnetEnabled(true))
	private.HandleFunc("POST /subnets/{id}/disable", s.setSubnetEnabled(false))
	private.HandleFunc("DELETE /subnets/{id}", s.deleteSubnet)
	private.HandleFunc("GET /subnets/health", s.localHealth)
	private.HandleFunc("POST /subnets/{id}/check", s.checkSubnet)
	private.HandleFunc("POST /subnets/{id}/health-check", s.useAsSubnetHealthCheck)
	private.HandleFunc("POST /scans", s.startScan)
	private.HandleFunc("GET /scans/{id}", s.scanStatus)
	private.HandleFunc("POST /connections/{id}/health-check", s.useAsHealthCheck)
	mux.Handle("/", s.Sessions.Require(private))
	return mux
}

type view struct {
	Title         string
	Active        string
	Authenticated bool
	Version       string
	Data          any
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, page, title string, data any) {
	tpl, ok := pages[page]
	if !ok {
		http.Error(w, "unknown page "+page, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err := tpl.Execute(w, view{
		Title:         title,
		Active:        page,
		Authenticated: s.Sessions.authenticated(r),
		Version:       tsvvpn.Version,
		Data:          data,
	})
	if err != nil {
		slog.Error("web: render page", "page", page, "err", err)
	}
}

func (s *Server) fragment(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := fragments.ExecuteTemplate(w, name, data); err != nil {
		slog.Error("web: render fragment", "fragment", name, "err", err)
	}
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	slog.Error("web", "err", err)
	http.Error(w, err.Error(), http.StatusInternalServerError)
}

func parsePages(names ...string) map[string]*template.Template {
	parsed := map[string]*template.Template{}
	for _, name := range names {
		parsed[name] = template.Must(template.New("layout.html").
			ParseFS(files, "templates/layout.html", "templates/"+name+".html", "templates/partials/*.html"))
	}
	return parsed
}
