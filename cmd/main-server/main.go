package main

import (
	"context"
	"embed"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	dashboardsvc "github.com/klouddb/klouddbshield/pkg/dashboard/service"
	mainserversvc "github.com/klouddb/klouddbshield/pkg/mainserver/service"
	"github.com/klouddb/klouddbshield/pkg/repository"
)

//go:embed dist/*
var staticFS embed.FS

// ------------------ Main ------------------
func main() {

	addr := flag.String("addr", ":8081", "HTTP listen address")
	dbDir := flag.String("dbdir", "/etc/klouddbshield/db", "SQLite storage directory (when -db-driver=sqlite)")
	dbDriver := flag.String("db-driver", "sqlite", "Storage driver: sqlite or postgres (overridden by KSHIELD_DB_DRIVER or server-node.yaml db_driver)")
	postgresURL := flag.String("postgres-url", "", "PostgreSQL connection URL (overridden by DATABASE_URL, MAIN_SERVER_DATABASE_URL, or server-node.yaml postgres_url)")
	tlsCert := flag.String("tls-cert", "", "TLS certificate file (defaults to /etc/klouddbshield/certs/server.crt when present)")
	tlsKey := flag.String("tls-key", "", "TLS private key file (defaults to /etc/klouddbshield/certs/server.key when present)")
	flag.Parse()

	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339})
	// log.Info().Str("addr", *addr).Str("dist", *dist).Msg("starting server")

	ctx := context.Background()

	// ensure directories
	if err := os.MkdirAll(*dbDir, 0o755); err != nil {
		fmt.Println("failed to create db dir")
		return
	}

	serverConfig, err := generateConfigFile()
	if err != nil {
		fmt.Println("Error while reading config file : ", err)
		return
	}

	// central DB connection (optional)
	// db, err := sql.Open("postgres", os.Getenv("DATABASE_URL"))
	// if err != nil {
	// 	log.Warn().Err(err).Msg("cannot open central DB")
	// 	db = nil
	// } else if err := db.Ping(); err != nil {
	// 	log.Warn().Err(err).Msg("cannot connect to central DB")
	// 	db = nil
	// }

	dbFilePath, err := generateServerDBFile(*dbDir)
	if err != nil {
		fmt.Println("Error while create server DB file ", err)
		return
	}

	storageCfg := resolveStorageConfig(repository.Config{
		Driver:      *dbDriver,
		SQLitePath:  dbFilePath,
		PostgresURL: *postgresURL,
	}, serverConfig)
	repo, err := repository.Open(ctx, storageCfg)
	if err != nil {
		fmt.Println("Error opening storage repository:", err)
		return
	}
	defer repo.Close()

	kshieldCfg := dashboardsvc.ConfigPathFromEnv()
	mainSvc := mainserversvc.New(repo)
	dashSvc := dashboardsvc.NewWithConfig(repo, kshieldCfg)

	app := &App{
		ServerConfig:      serverConfig,
		DBFilePath:        dbFilePath,
		Repo:              repo,
		Svc:               mainSvc,
		DashboardSvc:      dashSvc,
		KshieldConfigPath: kshieldCfg,
		WSHub:             NewHub(),
	}

	log.Info().Str("driver", storageCfg.EffectiveDriver()).Msg("storage repository initialized")

	fmt.Println("Running WebSocket Hub...")
	go app.WSHub.Run()

	if err := repo.EnsureSchema(ctx); err != nil {
		fmt.Println("Error creating storage schema:", err)
		return
	}

	r := mux.NewRouter()

	r.Methods(http.MethodOptions).HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	r.HandleFunc("/api/overview", app.overviewHandler).Methods(http.MethodGet)
	r.HandleFunc("/api/hosts", app.hostsHandler).Methods(http.MethodGet)
	r.HandleFunc("/api/violations", app.violationsHandler).Methods(http.MethodGet)
	r.HandleFunc("/api/critical-checks", app.criticalChecksHandler).Methods(http.MethodGet)
	r.HandleFunc("/api/runs", app.runsHandler).Methods(http.MethodGet)
	r.HandleFunc("/api/strategic", app.strategicHandler).Methods(http.MethodGet)
	r.HandleFunc("/api/fleet/categories", app.fleetCategoriesHandler).Methods(http.MethodGet)
	r.HandleFunc("/api/guc/drift", app.gucDriftHandler).Methods(http.MethodGet)
	r.HandleFunc("/api/guc/baseline", app.gucBaselineGetHandler).Methods(http.MethodGet)
	r.HandleFunc("/api/guc/baseline", app.gucBaselinePutHandler).Methods(http.MethodPut)
	r.HandleFunc("/api/guc/snapshots", app.gucSnapshotsHandler).Methods(http.MethodGet)
	r.HandleFunc("/api/guc/ignores", app.gucIgnoresGetHandler).Methods(http.MethodGet)
	r.HandleFunc("/api/guc/ignores", app.gucIgnoresPutHandler).Methods(http.MethodPut)
	r.HandleFunc("/api/guc/groups", app.gucGroupsGetHandler).Methods(http.MethodGet)
	r.HandleFunc("/api/guc/groups", app.gucGroupsPostHandler).Methods(http.MethodPost)
	r.HandleFunc("/api/guc/groups/{groupId}", app.gucGroupDeleteHandler).Methods(http.MethodDelete)
	r.HandleFunc("/api/guc/groups/{groupId}/members", app.gucGroupMembersPutHandler).Methods(http.MethodPut)
	r.HandleFunc("/api/policies", app.policiesHandler).Methods(http.MethodGet)
	r.HandleFunc("/api/collector/config", app.collectorConfigHandler).Methods(http.MethodGet)
	r.HandleFunc("/api/scanner/hba", app.hbaScannerHandler).Methods(http.MethodGet)
	r.HandleFunc("/api/scanner/ssl", app.sslScannerHandler).Methods(http.MethodGet)
	r.HandleFunc("/api/scanner/pii", app.piiScannerHandler).Methods(http.MethodGet)
	r.HandleFunc("/api/scanner/logparser", app.logParserScannerHandler).Methods(http.MethodGet)
	r.HandleFunc("/api/scanner/log-readiness", app.logReadinessHandler).Methods(http.MethodGet)
	r.HandleFunc("/api/reports/inactive-users", app.inactiveUsersReportHandler).Methods(http.MethodGet)
	r.HandleFunc("/api/reports/common-users", app.commonUsersReportHandler).Methods(http.MethodGet)
	r.HandleFunc("/api/runs/{runId}/html", app.runHTMLHandler).Methods(http.MethodGet)
	r.HandleFunc("/api/servers", app.serverHandler).Methods(http.MethodGet)
	r.HandleFunc("/api/servers/{serverId}", app.serverHandler).Methods(http.MethodGet)
	r.HandleFunc("/api/backup-compliance/summary", app.backupComplianceSummaryHandler).Methods(http.MethodGet)
	r.HandleFunc("/api/backup-compliance/history", app.backupComplianceHistoryHandler).Methods(http.MethodGet)
	r.HandleFunc("/api/backup-compliance/policy", app.backupCompliancePolicyGetHandler).Methods(http.MethodGet)
	r.HandleFunc("/api/backup-compliance/policy", app.backupCompliancePolicyPutHandler).Methods(http.MethodPut)

	r.HandleFunc("/ws", app.WebSocketHandler).Methods(http.MethodGet)

	r.HandleFunc("/api/collector/register", app.requireCollectorToken(app.collectorRegisterHandler)).Methods(http.MethodPost)
	r.HandleFunc("/api/collector/heartbeat", app.requireCollectorToken(app.collectorHeartbeatHandler)).Methods(http.MethodPost)
	r.HandleFunc("/api/collector/activity", app.requireCollectorToken(app.collectorActivityHandler)).Methods(http.MethodPost)
	r.HandleFunc("/api/collector/logs", app.requireCollectorToken(app.collectorLogsHandler)).Methods(http.MethodPost)
	r.HandleFunc("/api/collector/runs", app.requireCollectorToken(app.collectorRunsHandler)).Methods(http.MethodPost)
	r.HandleFunc("/api/collector/data", app.requireCollectorToken(app.clientDataPostHandler)).Methods(http.MethodPost)
	r.HandleFunc("/api/collector/pii", app.requireCollectorToken(app.piiDataPostHandler)).Methods(http.MethodPost)
	r.HandleFunc("/api/collector/backup-compliance", app.requireCollectorToken(app.backupComplianceDataPostHandler)).Methods(http.MethodPost)
	r.HandleFunc("/api/collector/nodes", app.collectorNodesHandler).Methods(http.MethodGet)
	r.HandleFunc("/api/collector/nodes/{id}", app.collectorNodeHandler).Methods(http.MethodGet)
	r.HandleFunc("/api/collector/nodes/{id}/runs", app.collectorNodeRunsHandler).Methods(http.MethodGet)
	r.HandleFunc("/api/collector/nodes/{id}/activity", app.collectorNodeActivityHandler).Methods(http.MethodGet)
	r.HandleFunc("/api/collector/nodes/{id}/logs", app.collectorNodeLogsHandler).Methods(http.MethodGet)

	r.PathPrefix("/").Handler(embeddedSPAHandler())

	//CORS handling
	corsHandler := handlers.CORS(
		handlers.AllowedOrigins([]string{
			"*",
		}),
		handlers.AllowedMethods([]string{
			"GET", "POST", "PUT", "DELETE", "OPTIONS",
		}),
		handlers.AllowedHeaders([]string{
			"Content-Type", "Authorization",
		}),
		handlers.AllowCredentials(),
	)

	handlerChain := loggingMiddleware(corsHandler(r))

	server := &http.Server{
		Addr:         *addr,
		Handler:      handlerChain,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// server := &http.Server{
	// 	Addr:         *addr,
	// 	Handler:      loggingMiddleware(r),
	// 	ReadTimeout:  10 * time.Second,
	// 	WriteTimeout: 10 * time.Second,
	// }

	tlsCfg, err := resolveTLSConfig(*tlsCert, *tlsKey)
	if err != nil {
		log.Fatal().Err(err).Msg("invalid tls configuration")
	}
	if tlsCfg.enabled {
		log.Info().Str("addr", *addr).Str("cert", tlsCfg.cert).Msg("starting HTTPS server")
		log.Fatal().Err(server.ListenAndServeTLS(tlsCfg.cert, tlsCfg.key)).Msg("server stopped")
	}
	log.Info().Str("addr", *addr).Msg("starting HTTP server")
	log.Fatal().Err(server.ListenAndServe()).Msg("server stopped")
}

func generateServerDBFile(dbDir string) (string, error) {
	// Ensure directory exists
	if err := os.MkdirAll(dbDir, 0o755); err != nil {
		return "", fmt.Errorf("failed to create db directory: %w", err)
	}

	dbPath := filepath.Join(dbDir, "main-server.sqlite")

	// Create file if it doesn't exist
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		file, err := os.OpenFile(dbPath, os.O_CREATE|os.O_RDWR, 0o644)
		if err != nil {
			return "", fmt.Errorf("failed to create server db file: %w", err)
		}
		_ = file.Close()
	}

	return dbPath, nil
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Info().Str("method", r.Method).Str("path", r.URL.Path).Dur("duration", time.Since(start)).Msg("http request")
	})
}

// func spaHandler(dist string, fs http.Handler) http.HandlerFunc {
// 	return func(w http.ResponseWriter, r *http.Request) {
// 		path := filepath.Join(dist, r.URL.Path)
// 		if _, err := os.Stat(path); err == nil {
// 			fs.ServeHTTP(w, r)
// 			return
// 		}
// 		http.ServeFile(w, r, filepath.Join(dist, "index.html"))
// 	}
// }

func embeddedSPAHandler() http.Handler {
	subFS, err := fs.Sub(staticFS, "dist")
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create sub FS")
	}

	fileServer := cacheStaticAssets(http.FileServer(http.FS(subFS)))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Backend routes must not be handled by SPA
		// if strings.HasPrefix(r.URL.Path, "/api") ||
		// 	strings.HasPrefix(r.URL.Path, "/collector") ||
		// 	r.URL.Path == "/ws" {
		// 	http.NotFound(w, r)
		// 	return
		// }
		if r.Method == http.MethodOptions ||
			strings.HasPrefix(r.URL.Path, "/api") ||
			strings.HasPrefix(r.URL.Path, "/collector") ||
			r.URL.Path == "/ws" {
			http.NotFound(w, r)
			return
		}

		// Try serving static file
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}

		if f, err := subFS.Open(path); err == nil {
			f.Close()
			fileServer.ServeHTTP(w, r)
			return
		}

		// SPA fallback — hash routes share index.html
		index, err := subFS.Open("index.html")
		if err != nil {
			http.Error(w, "index.html not found in embedded frontend", http.StatusInternalServerError)
			return
		}
		defer index.Close()

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.Copy(w, index)
	})
}

func cacheStaticAssets(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			path := r.URL.Path
			switch {
			case strings.HasSuffix(path, ".css"),
				strings.HasSuffix(path, ".js"),
				strings.HasSuffix(path, ".png"),
				strings.HasSuffix(path, ".jpg"),
				strings.HasSuffix(path, ".jpeg"),
				strings.HasSuffix(path, ".webp"),
				strings.HasSuffix(path, ".svg"),
				strings.HasSuffix(path, ".woff"),
				strings.HasSuffix(path, ".woff2"):
				w.Header().Set("Cache-Control", "public, max-age=86400")
			}
		}
		next.ServeHTTP(w, r)
	})
}
