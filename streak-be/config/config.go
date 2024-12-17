package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// These variables are set during compilation.
var (
	AppName    string
	AppVersion string
	BuildType  string
)

type Config struct {
	AppName               string
	AppVersion            string
	BuildType             string
	Env                   string `validate:"required,oneof=development production"`
	Host                  string `validate:"required,ip"`
	Port                  string `validate:"required,gte=0"`
	DatabaseURL           string `validate:"required"`
	SMTPHost              string `validate:"required"`
	SMTPUsername          string `validate:"required"`
	SMTPPassword          string `validate:"required"`
	SenderEmail           string `validate:"required"` // SenderEmail is the email address from which emails will be sent.
	S3BucketName          string `validate:"required"`
	S3Endpoint            string `validate:"required"`
	S3DefaultRegion       string `validate:"required"`
	AWSAccessKeyID        string `validate:"required"`
	AWSAccessKeySecret    string `validate:"required"`
	GoogleClientID        string // GoogleClientID is the client ID for Google OAuth2 authentication.
	GoogleClientSecret    string
	AccessTokenSecret     string `validate:"required"`
	RefreshTokenSecret    string `validate:"required"`
	CommonTokenSecret     string `validate:"required"`
	GoogleOAuth2Config    *oauth2.Config
	AllowedOrigins        []string
	AccessTokenExpiresIn  time.Duration `validate:"required"`
	RefreshTokenExpiresIn time.Duration `validate:"required"`
	CommonTokenExpiresIn  time.Duration `validate:"required"`
	SMTPPort              int           `validate:"required"`
	IsDev                 bool
	UseDevTLS             bool
}

func Load() (*Config, error) {
	env, err := godotenv.Unmarshal(strings.Join(os.Environ(), "\n"))
	if err != nil {
		return nil, fmt.Errorf("failed to read environment variables: %w", err)
	}
	// Read from .env file if present.
	if fileEnv, readErr := godotenv.Read(env["ENV_FILE"]); readErr != nil {
		for key, value := range fileEnv {
			env[key] = value
		}
	}

	var cfg Config
	var errs []error

	buildInfo, ok := debug.ReadBuildInfo()
	if !ok {
		return nil, errors.New("failed to get build info")
	}

	cfg.AppName = filepath.Base(buildInfo.Main.Path)
	cfg.AppVersion = AppVersion
	cfg.BuildType = BuildType
	cfg.Env = env["ENV"]
	cfg.Host = env["HOST"]
	cfg.Port = env["PORT"]
	cfg.DatabaseURL = env["DATABASE_URL"]
	cfg.SMTPHost = env["SMTP_HOST"]
	cfg.SMTPUsername = env["SMTP_USERNAME"]
	cfg.SMTPPassword = env["SMTP_PASSWORD"]
	cfg.SenderEmail = env["SENDER_EMAIL"]
	cfg.S3BucketName = env["S3_BUCKET_NAME"]
	cfg.S3Endpoint = env["S3_ENDPOINT"]
	cfg.S3DefaultRegion = env["S3_DEFAULT_REGION"]
	cfg.AWSAccessKeyID = env["AWS_ACCESS_KEY_ID"]
	cfg.AWSAccessKeySecret = env["AWS_ACCESS_KEY_SECRET"]
	cfg.AccessTokenSecret = env["ACCESS_TOKEN_SECRET"]
	cfg.RefreshTokenSecret = env["REFRESH_TOKEN_SECRET"]
	cfg.CommonTokenSecret = env["COMMON_TOKEN_SECRET"]
	cfg.AllowedOrigins = strings.Split(env["ALLOWED_ORIGINS"], ",")
	if cfg.AccessTokenExpiresIn, err = time.ParseDuration(env["ACCESS_TOKEN_EXPIRES_IN"]); err != nil {
		errs = append(errs, fmt.Errorf("failed to parse access token expires in: %w", err))
	}
	if cfg.RefreshTokenExpiresIn, err = time.ParseDuration(env["REFRESH_TOKEN_EXPIRES_IN"]); err != nil {
		errs = append(errs, fmt.Errorf("failed to parse refresh token expires in: %w", err))
	}
	if cfg.CommonTokenExpiresIn, err = time.ParseDuration(env["COMMON_TOKEN_EXPIRES_IN"]); err != nil {
		errs = append(errs, fmt.Errorf("failed to parse common token expires in: %w", err))
	}
	if cfg.SMTPPort, err = strconv.Atoi(env["SMTP_PORT"]); err != nil {
		errs = append(errs, fmt.Errorf("failed to parse SMTP port: %w", err))
	}
	cfg.IsDev = env["ENV"] != "production"
	cfg.UseDevTLS = env["USE_DEV_TLS"] == "true"
	cfg.GoogleClientID = env["GOOGLE_CLIENT_ID"]
	cfg.GoogleClientSecret = env["GOOGLE_CLIENT_SECRET"]
	cfg.GoogleOAuth2Config = &oauth2.Config{
		ClientID:     cfg.GoogleClientID,
		ClientSecret: cfg.GoogleClientSecret,
		Endpoint:     google.Endpoint,
		RedirectURL:  fmt.Sprintf("https://%s/v1/auth/oauth2/callback/google", cfg.Host+":"+cfg.Port),
		Scopes:       []string{"openid email", "openid profile"},
	}

	if err = validator.New().Struct(cfg); err != nil {
		errs = append(errs, fmt.Errorf("failed to validate config: %w", err))
	}

	err = errors.Join(errs...)

	return &cfg, err
}
