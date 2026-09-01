package main

import (
	"context"
	"errors"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	tsvvpn "tsv-vpn"
	"tsv-vpn/internal/crypto"
	"tsv-vpn/internal/db"
	"tsv-vpn/internal/discover"
	"tsv-vpn/internal/health"
	"tsv-vpn/internal/logbuf"
	"tsv-vpn/internal/logging"
	"tsv-vpn/internal/run"
	"tsv-vpn/internal/supervise"
	"tsv-vpn/internal/tailnet"
	"tsv-vpn/internal/tunnel"
	"tsv-vpn/internal/web"
)

const (
	charonBinary  = "/usr/lib/ipsec/charon"
	xl2tpdRunDir  = "/var/run/xl2tpd"
	logLinesKept  = 200
	socketTimeout = 30 * time.Second
)

func main() {
	run := start
	logDir := env("TSV_VPN_LOG_DIR", "/data/logs")
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "hash-password":
			run = func() error { return hashPassword(os.Args[2:]) }
			logDir = ""
		case "reset-password":
			run = resetPassword
			logDir = ""
		}
	}

	closer, err := logging.Setup(logDir, logRetention())
	if err != nil {
		log.Fatalf("tsv-vpn: logging: %v", err)
	}
	defer closer.Close()

	if err := run(); err != nil {
		slog.Error("tsv-vpn exited", "err", err)
		closer.Close()
		os.Exit(1)
	}
}

// TSV_VPN_LOG_RETENTION (a Go duration) overrides the 30-day default.
func logRetention() time.Duration {
	parsed, err := time.ParseDuration(os.Getenv("TSV_VPN_LOG_RETENTION"))
	if err != nil {
		return logging.DefaultRetention
	}
	return parsed
}

func start() error {
	var (
		runDir     = env("TSV_VPN_RUN_DIR", "/run/tsv-vpn")
		listenAddr = env("TSV_VPN_LISTEN", ":8080")
		stateDir   = env("TS_STATE_DIR", "/var/lib/tailscale")
		hostname   = env("TS_HOSTNAME", "tsv-vpn")
	)

	key, err := crypto.LoadKey(env("MASTER_KEY_FILE", "/run/secrets/tsv_vpn_master_key"))
	if err != nil {
		return err
	}
	cipher, err := crypto.New(key)
	if err != nil {
		return err
	}
	store, err := db.Open(env("TSV_VPN_DB", "/data/tsv-vpn.db"), cipher)
	if err != nil {
		return err
	}
	defer store.Close()

	if err := os.MkdirAll(runDir, 0o700); err != nil {
		return err
	}
	// xl2tpd-control answers on a FIFO it creates in this directory.
	if err := os.MkdirAll(xl2tpdRunDir, 0o755); err != nil {
		return err
	}
	// The ppp hooks are unauthenticated: loopback listener only, never the
	// published admin port.
	hookListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer hookListener.Close()
	if err := tunnel.InstallHooks(tunnel.DefaultPPPDir, hookListener.Addr().String()); err != nil {
		return err
	}
	if err := tunnel.LinkCHAPSecrets(tunnel.DefaultPPPDir, runDir); err != nil {
		return err
	}

	logs := logbuf.New(logLinesKept, connectionNames(store))
	var manager *tunnel.Manager
	supervisor := &supervise.Supervisor{OnLine: func(source, line string) {
		logs.Add(source, line)
		slog.Info("daemon", "source", source, "line", line)
		if line == "started" && (source == "charon" || source == "xl2tpd") {
			manager.Invalidate()
		}
	}}
	tailscale := tailnet.Client{Runner: run.Exec{}, Socket: tailnet.DefaultSocket}
	manager = tunnel.New(tunnel.Options{
		Store:   store,
		Dir:     runDir,
		Runner:  run.Exec{},
		Control: tunnel.XL2TPDControl{Runner: run.Exec{}, Path: filepath.Join(runDir, "l2tp-control")},
		Logs:    logs,
		Tailnet: tailscale,
	})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := manager.Prerender(ctx); err != nil {
		return err
	}

	checker := &health.Checker{
		Store:    store,
		Tunnels:  manager,
		Pinger:   health.InterfacePinger{},
		Logs:     logs,
		Interval: duration("TSV_VPN_HEALTH_INTERVAL"),
	}
	reporter := health.Reporter{Store: store, Tunnels: manager, Backend: func(ctx context.Context) (string, error) {
		status, err := tailscale.Status(ctx)
		return status.BackendState, err
	}}

	credentials := &web.Credentials{Store: store, EnvHash: []byte(os.Getenv("ADMIN_PASSWORD_HASH"))}
	if credentials.NeedsSetup() {
		slog.Warn("no admin password set; the web ui answers unauthenticated until one is chosen")
	}

	ui := &web.Server{
		Store:    store,
		Tunnels:  manager,
		Checks:   checker,
		Gateway:  discover.Preflight{Pinger: discover.ICMPPinger{}},
		Tailnet:  tailscale,
		Hostname: hostname,
		Scanner:  discover.Scan{},
		Prober:   discover.Probe{},
		Logs:     logs,
		Sessions: web.NewSessions(credentials),
	}

	hookServer := &http.Server{Handler: manager.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := hookServer.Serve(hookListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("hook listener", "err", err)
		}
	}()
	defer hookServer.Close()

	mux := http.NewServeMux()
	mux.Handle("/", ui.Handler())
	mux.Handle("GET /healthz", reporter.Handler())

	server := &http.Server{Addr: listenAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("web listener", "err", err)
		}
	}()

	slog.Info("tsv-vpn listening", "addr", listenAddr, "version", tsvvpn.Version)

	daemons := []supervise.Process{
		{Name: "tailscaled", Path: "tailscaled", Args: []string{
			"--state=" + filepath.Join(stateDir, "tailscaled.state"),
			"--socket=" + tailnet.DefaultSocket,
			"--port=41641",
		}},
		{Name: "charon", Path: charonBinary},
		{Name: "xl2tpd", Path: "xl2tpd", Args: []string{
			"-D",
			"-c", filepath.Join(runDir, "xl2tpd.conf"),
			"-C", filepath.Join(runDir, "l2tp-control"),
		}},
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		supervisor.Run(ctx, daemons...)
	}()

	// Without an auth key "tailscale up" waits for an interactive login;
	// the reconciler must not be behind it.
	go func() {
		if err := joinTailnet(ctx, tailscale, store, hostname); err != nil {
			slog.Error("tailnet join", "err", err)
		}
	}()
	go checker.Run(ctx)
	manager.Run(ctx)

	<-done

	// Drain in-flight admin requests instead of cutting them off.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdownCtx)
	return nil
}

func joinTailnet(ctx context.Context, client tailnet.Client, store *db.Store, hostname string) error {
	if err := client.WaitForSocket(ctx, socketTimeout); err != nil {
		return err
	}
	routes, err := store.AdvertisedRoutes()
	if err != nil {
		return err
	}
	exitNode, err := store.ExitNode()
	if err != nil {
		return err
	}
	return client.Up(ctx, hostname, os.Getenv("TS_AUTHKEY"), routes, exitNode)
}

func connectionNames(store *db.Store) func() []string {
	return func() []string {
		conns, err := store.ListConnections()
		if err != nil {
			return nil
		}
		names := make([]string, 0, len(conns))
		for _, conn := range conns {
			names = append(names, conn.Name)
		}
		return names
	}
}

// Zero keeps the checker's default; the rig shortens it.
func duration(name string) time.Duration {
	parsed, err := time.ParseDuration(os.Getenv(name))
	if err != nil {
		return 0
	}
	return parsed
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
