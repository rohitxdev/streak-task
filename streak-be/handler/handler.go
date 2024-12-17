package handler

import (
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-playground/validator"
	gojson "github.com/goccy/go-json"
	"github.com/labstack/echo-contrib/echoprometheus"
	"github.com/labstack/echo-contrib/pprof"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/oklog/ulid/v2"
	"github.com/rohitxdev/go-api-starter/assets"
	"github.com/rohitxdev/go-api-starter/blobstore"
	"github.com/rohitxdev/go-api-starter/config"
	"github.com/rohitxdev/go-api-starter/email"
	"github.com/rohitxdev/go-api-starter/repo"
)

type Service struct {
	BlobStore *blobstore.Store
	Config    *config.Config
	Email     *email.Client
	Repo      *repo.Repo
}

func (s *Service) Close() error {
	if err := s.Repo.Close(); err != nil {
		return fmt.Errorf("failed to close repo: %w", err)
	}
	return nil
}

type Handler struct {
	*Service
}

// Custom view renderer
type renderer struct {
	templates *template.Template
}

func (t renderer) Render(w io.Writer, name string, data any, c echo.Context) error {
	return t.templates.ExecuteTemplate(w, name+".tmpl", data)
}

// Custom request validator
type requestValidator struct {
	validator *validator.Validate
}

func (v requestValidator) Validate(i any) error {
	if err := v.validator.Struct(i); err != nil {
		return echo.NewHTTPError(http.StatusUnprocessableEntity, err)
	}
	return nil
}

// Custom JSON serializer & deserializer
type jsonSerializer struct{}

func (s jsonSerializer) Serialize(c echo.Context, data any, indent string) error {
	enc := gojson.NewEncoder(c.Response())
	enc.SetIndent("", indent)
	return enc.Encode(data)
}

func (s jsonSerializer) Deserialize(c echo.Context, v any) error {
	dec := gojson.NewDecoder(c.Request().Body)
	err := dec.Decode(v)
	if ute, ok := err.(*gojson.UnmarshalTypeError); ok {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Unmarshal type error: expected=%v, got=%v, field=%v, offset=%v", ute.Type, ute.Value, ute.Field, ute.Offset)).SetInternal(err)
	} else if se, ok := err.(*gojson.SyntaxError); ok {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Syntax error: offset=%v, error=%v", se.Offset, se.Error())).SetInternal(err)
	}
	return err
}

func New(svc *Service) (*echo.Echo, error) {
	h := Handler{Service: svc}

	e := echo.New()

	e.JSONSerializer = jsonSerializer{}

	e.Validator = requestValidator{
		validator: validator.New(),
	}

	e.IPExtractor = echo.ExtractIPFromXFFHeader(
		echo.TrustLoopback(false),   // e.g. ipv4 start with 127.
		echo.TrustLinkLocal(false),  // e.g. ipv4 start with 169.254
		echo.TrustPrivateNet(false), // e.g. ipv4 start with 10. or 192.168
	)

	pageTemplates, err := template.ParseFS(assets.FS, "templates/pages/*.tmpl")
	if err != nil {
		return nil, fmt.Errorf("failed to parse templates: %w", err)
	}
	e.Renderer = renderer{
		templates: pageTemplates,
	}

	e.HTTPErrorHandler = func(err error, c echo.Context) {
		defer func() {
			if err != nil {
				slog.Error("HTTP error response failure", slog.String("id", c.Response().Header().Get(echo.HeaderXRequestID)), slog.String("error", err.Error()))
			}
		}()

		var res Response
		if httpErr, ok := err.(*echo.HTTPError); ok {
			switch msg := httpErr.Message.(type) {
			case string:
				res.Message = msg
			case error:
				res.Message = msg.Error()
			default:
				res.Message = httpErr.Error()
			}
			err = c.JSON(httpErr.Code, res)
		} else {
			res.Message = MsgSomethingWentWrong
			err = c.JSON(http.StatusInternalServerError, res)
		}
	}

	//Pre-router middlewares
	if !h.Config.IsDev {
		e.Pre(middleware.CSRF())
	}

	e.Pre(middleware.Secure())

	e.Pre(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins:                             h.Config.AllowedOrigins,
		AllowCredentials:                         true,
		UnsafeWildcardOriginWithAllowCredentials: h.Config.IsDev,
	}))

	e.Pre(middleware.StaticWithConfig(middleware.StaticConfig{
		Root:       "public",
		Filesystem: http.FS(assets.FS),
	}))

	e.Pre(middleware.RequestIDWithConfig(middleware.RequestIDConfig{
		Generator: ulid.Make().String,
	}))

	e.Pre(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		LogRequestID:    true,
		LogRemoteIP:     true,
		LogProtocol:     true,
		LogURI:          true,
		LogMethod:       true,
		LogStatus:       true,
		LogLatency:      true,
		LogResponseSize: true,
		LogReferer:      true,
		LogUserAgent:    true,
		LogError:        true,
		LogHost:         true,
		LogValuesFunc: func(c echo.Context, v middleware.RequestLoggerValues) error {
			status := v.Status
			var errStr string
			if httpErr, ok := v.Error.(*echo.HTTPError); ok {
				if httpErr.Code == http.StatusInternalServerError {
					errStr = httpErr.Error()
				}
			} else if v.Error != nil {
				// Due to a bug in echo, when the error is not an echo.HTTPError, even though the status code sent is 500, it's logged as 200 in this middleware. We need to manually set the status code in the log to 500.
				status = http.StatusInternalServerError
			}

			var userID uint64
			if user, ok := c.Get("user").(*repo.User); ok && (user != nil) {
				userID = user.ID
			}

			slog.Info("http request",
				slog.String("id", v.RequestID),
				slog.String("clientIp", v.RemoteIP),
				slog.String("protocol", v.Protocol),
				slog.String("uri", v.URI),
				slog.String("method", v.Method),
				slog.Int64("durationMs", v.Latency.Milliseconds()),
				slog.Int64("bytesOut", v.ResponseSize),
				slog.String("host", v.Host),
				slog.String("ua", v.UserAgent),
				slog.String("referer", v.Referer),
				slog.Uint64("userId", userID),
				slog.Int("status", status),
				slog.String("error", errStr),
			)
			return nil
		},
	}))

	e.Pre(middleware.RemoveTrailingSlash())

	//Post-router middlewares
	e.Use(middleware.GzipWithConfig(middleware.GzipConfig{
		Skipper: func(c echo.Context) bool {
			return !strings.Contains(c.Request().Header.Get("Accept-Encoding"), "gzip") || strings.HasPrefix(c.Path(), "/metrics")
		},
	}))

	e.Use(middleware.Decompress())

	e.Use(middleware.RecoverWithConfig(middleware.RecoverConfig{
		LogErrorFunc: func(c echo.Context, err error, stack []byte) error {
			slog.Error("http handler panic", slog.String("id", c.Response().Header().Get(echo.HeaderXRequestID)), slog.String("error", err.Error()), slog.String("stack", string(stack)))
			return nil
		}},
	))

	// This middleware causes data races, but it's not a big deal. See https://github.com/labstack/echo/issues/1761
	e.Use(middleware.TimeoutWithConfig(middleware.TimeoutConfig{
		Timeout: time.Second * 10, Skipper: func(c echo.Context) bool {
			return strings.HasPrefix(c.Path(), "/debug/pprof")
		},
	}))

	e.Use(echoprometheus.NewMiddleware("api"))

	pprof.Register(e)

	mountRoutes(e, &h)

	return e, nil
}
