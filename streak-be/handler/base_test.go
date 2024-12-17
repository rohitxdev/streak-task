package handler_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/rohitxdev/go-api-starter/blobstore"
	"github.com/rohitxdev/go-api-starter/config"
	"github.com/rohitxdev/go-api-starter/database"
	"github.com/rohitxdev/go-api-starter/email"
	"github.com/rohitxdev/go-api-starter/handler"
	"github.com/rohitxdev/go-api-starter/repo"
	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	slog.SetLogLoggerLevel(slog.LevelWarn)
	os.Exit(m.Run())
}

type httpRequestOpts struct {
	query   map[string]string
	body    echo.Map
	headers map[string]string
	method  string
	path    string
}

func createHttpRequest(opts *httpRequestOpts) (*http.Request, error) {
	url, err := url.Parse(opts.path)
	if err != nil {
		return nil, err
	}
	q := url.Query()
	for key, value := range opts.query {
		q.Set(key, value)
	}
	url.RawQuery = q.Encode()
	j, err := json.Marshal(opts.body)
	if err != nil {
		return nil, err
	}
	req := httptest.NewRequest(opts.method, url.String(), bytes.NewReader(j))
	for key, value := range opts.headers {
		req.Header.Set(key, value)
	}
	return req, err
}

func TestBaseRoutes(t *testing.T) {
	defer func() {
		// The prometheus exporter middleware causes panics when running tests so it's necessary to use recover().
		r := recover()
		if r != nil {
			t.Logf("panic: %v", r)
		}
	}()
	//Load config
	cfg, err := config.Load()
	assert.NoError(t, err)

	//Connect to postgres database
	db, err := database.NewPostgreSQL(cfg.DatabaseURL)
	assert.NoError(t, err)
	defer db.Close()

	// Create repo
	r, err := repo.New(db)
	assert.NoError(t, err)
	defer r.Close()

	bs, err := blobstore.New(cfg.S3Endpoint, cfg.S3DefaultRegion, cfg.AWSAccessKeyID, cfg.AWSAccessKeySecret)
	assert.NoError(t, err)

	e, err := email.New(&email.SMTPCredentials{
		Host:               cfg.SMTPHost,
		Port:               cfg.SMTPPort,
		Username:           cfg.SMTPUsername,
		Password:           cfg.SMTPPassword,
		InsecureSkipVerify: cfg.IsDev,
	})
	assert.NoError(t, err)

	h, err := handler.New(&handler.Service{
		BlobStore: bs,
		Config:    cfg,
		Repo:      r,
		Email:     e,
	})
	assert.NoError(t, err)

	t.Run("GET /", func(t *testing.T) {
		t.Parallel()
		req, err := createHttpRequest(&httpRequestOpts{
			method: http.MethodGet,
			path:   "/",
		})
		assert.NoError(t, err)
		res := httptest.NewRecorder()
		h.ServeHTTP(res, req)
		assert.Equal(t, http.StatusOK, res.Code)
	})

	t.Run("GET /config", func(t *testing.T) {
		t.Parallel()
		req, err := createHttpRequest(&httpRequestOpts{
			method: http.MethodGet,
			path:   "/config",
		})
		assert.NoError(t, err)
		res := httptest.NewRecorder()
		h.ServeHTTP(res, req)
		assert.Equal(t, http.StatusOK, res.Code)
	})
}
