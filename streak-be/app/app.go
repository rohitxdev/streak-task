package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"time"

	"github.com/lmittmann/tint"
	"github.com/rohitxdev/go-api-starter/blobstore"
	"github.com/rohitxdev/go-api-starter/config"
	"github.com/rohitxdev/go-api-starter/cryptoutil"
	"github.com/rohitxdev/go-api-starter/database"
	"github.com/rohitxdev/go-api-starter/email"
	"github.com/rohitxdev/go-api-starter/handler"
	"github.com/rohitxdev/go-api-starter/repo"
	"go.uber.org/automaxprocs/maxprocs"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func Run() error {
	// Set GOMAXPROCS to match the Linux container CPU quota.
	if _, err := maxprocs.Set(); err != nil {
		return fmt.Errorf("failed to set maxprocs: %w", err)
	}

	// Load config.
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Set up logger.
	logOpts := slog.HandlerOptions{
		Level: slog.LevelDebug,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Value.Any() == nil || a.Value.String() == "" {
				return slog.Attr{}
			}
			if a.Key == "userId" && a.Value.Uint64() == 0 {
				return slog.Attr{}
			}
			return a
		},
	}
	var logHandler slog.Handler = slog.NewJSONHandler(os.Stderr, &logOpts)
	if cfg.IsDev {
		logHandler = tint.NewHandler(os.Stderr, &tint.Options{
			Level:       logOpts.Level,
			ReplaceAttr: logOpts.ReplaceAttr,
			TimeFormat:  time.Kitchen,
		})
	}
	slog.SetDefault(slog.New(logHandler))
	slog.Debug("starting app",
		slog.String("name", cfg.AppName),
		slog.String("version", cfg.AppVersion),
		slog.String("buildType", cfg.BuildType),
		slog.String("env", cfg.Env),
		slog.Int("maxProcs", runtime.GOMAXPROCS(0)),
		slog.String("platform", fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)),
	)

	// Connect to postgres database.
	db, err := database.NewPostgreSQL(cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	// Create repo for interacting with the database.
	r, err := repo.New(db)
	if err != nil {
		return fmt.Errorf("failed to create repo: %w", err)
	}

	// Create blobstore for storing files.
	bs, err := blobstore.New(cfg.S3Endpoint, cfg.S3DefaultRegion, cfg.AWSAccessKeyID, cfg.AWSAccessKeySecret)
	if err != nil {
		return fmt.Errorf("failed to create s3 client: %w", err)
	}

	e, err := email.New(&email.SMTPCredentials{
		Host:               cfg.SMTPHost,
		Port:               cfg.SMTPPort,
		Username:           cfg.SMTPUsername,
		Password:           cfg.SMTPPassword,
		InsecureSkipVerify: cfg.IsDev,
	})
	if err != nil {
		return fmt.Errorf("failed to create email client: %w", err)
	}

	s := handler.Service{
		BlobStore: bs,
		Config:    cfg,
		Email:     e,
		Repo:      r,
	}
	defer s.Close()

	h, err := handler.New(&s)
	if err != nil {
		return fmt.Errorf("failed to create http handler: %w", err)
	}

	errCh := make(chan error)
	address := net.JoinHostPort(cfg.Host, cfg.Port)
	isDevTLS := cfg.IsDev && cfg.UseDevTLS

	// Start HTTP server.
	go func() {
		if isDevTLS {
			certPath, keyPath, isFromCache, cryptoErr := cryptoutil.GenerateSelfSignedCert()
			if cryptoErr != nil {
				errCh <- fmt.Errorf("failed to generate self-signed certificate: %w", cryptoErr)
			}
			if !isFromCache {
				slog.Info("generated self-signed tls certificate and key")
			}
			errCh <- http.ListenAndServeTLS(address, certPath, keyPath, h)
		} else {
			// Stdlib supports HTTP/2 by default when serving over TLS, but has to be explicitly enabled otherwise.
			h2Handler := h2c.NewHandler(h, &http2.Server{})
			errCh <- http.ListenAndServe(address, h2Handler)
		}
	}()

	protocol := "http"
	if isDevTLS {
		protocol = "https"
	}
	slog.Info(fmt.Sprintf("server is listening on %s://%s", protocol, address))

	// Shut down HTTP server gracefully.
	ctx := context.Background()
	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt)
	defer cancel()

	select {
	case <-ctx.Done():
		ctx, cancel = context.WithTimeout(ctx, time.Second*10)
		defer cancel()

		if err = h.Shutdown(ctx); err != nil {
			return fmt.Errorf("failed to shutdown http server: %w", err)
		}

		slog.Debug("shut down http server gracefully")
	case err = <-errCh:
		if err != nil && !errors.Is(err, net.ErrClosed) {
			err = fmt.Errorf("failed to start http server: %w", err)
		}
	}
	return err
}
