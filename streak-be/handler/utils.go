package handler

import (
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/rohitxdev/go-api-starter/cryptoutil"
	"github.com/rohitxdev/go-api-starter/repo"
	"golang.org/x/time/rate"
)

const (
	MsgUserNotLoggedIn         = "User is not logged in"
	MsgUserNotFound            = "User not found"
	MsgUserAlreadyExists       = "User already exists"
	MsgAccountStatusNotActive  = "Account status is not " + repo.AccountStatusActive
	MsgAccountStatusNotPending = "Account status is not " + repo.AccountStatusPending
	MsgUnauthorizedCallbackURL = "Unauthorized callback URL"
	MsgJWTVerificationFailed   = "JWT verification failed"
	MsgIncorrectPassword       = "Incorrect password"
	MsgInsufficientPrivileges  = "Insufficient privileges"
	MsgTooManyRequests         = "Too many requests. Please try again later."
	MsgSomethingWentWrong      = "Something went wrong"
)

type Response struct {
	Message string `json:"message,omitempty"`
	Success bool   `json:"success"`
}

type ResponseWithPayload[T any] struct {
	Payload T      `json:"payload,omitempty"`
	Message string `json:"message,omitempty"`
	Success bool   `json:"success"`
}

type role string

const (
	RoleUser  role = repo.RoleUser
	RoleAdmin role = repo.RoleAdmin
)

var roles = map[role]uint8{
	RoleUser:  1,
	RoleAdmin: 2,
}

func (h Handler) checkAuth(c echo.Context, r role) (*repo.User, error) {
	accessTokenCookie, err := c.Cookie("accessToken")
	if err != nil {
		return nil, echo.NewHTTPError(http.StatusUnauthorized, MsgUserNotLoggedIn)
	}
	userID, err := cryptoutil.VerifyJWT[uint64](accessTokenCookie.Value, h.Config.AccessTokenSecret)
	if err != nil {
		return nil, echo.NewHTTPError(http.StatusUnauthorized, MsgJWTVerificationFailed)
	}
	user, err := h.Repo.GetUserById(c.Request().Context(), userID)
	if err != nil {
		return nil, echo.NewHTTPError(http.StatusNotFound, MsgUserNotFound)
	}
	if user.AccountStatus != repo.AccountStatusActive {
		return nil, echo.NewHTTPError(http.StatusForbidden, MsgAccountStatusNotActive)
	}
	if roles[role(user.Role)] < roles[role(r)] {
		return nil, echo.NewHTTPError(http.StatusForbidden, MsgInsufficientPrivileges)
	}
	return user, nil
}

// bindAndValidate binds path params, query params and the request body into provided type `i` and validates provided `i`. `i` must be a pointer. The default binder binds body based on Content-Type header. Validator must be registered using `Echo#Validator`.
func bindAndValidate(c echo.Context, i any) error {
	var err error
	if err = c.Bind(i); err != nil {
		return err
	}
	binder := echo.DefaultBinder{}
	if err = binder.BindHeaders(c, i); err != nil {
		return err
	}
	if err = c.Validate(i); err != nil {
		return err
	}
	return err
}

func canonicalizeEmail(email string) string {
	email = strings.TrimSpace(email)
	email = strings.ToLower(email)
	parts := strings.Split(email, "@")
	username := parts[0]
	domain := parts[1]
	if strings.Contains(username, "+") {
		username = strings.Split(username, "+")[0]
	}
	username = strings.ReplaceAll(username, ".", "")
	return username + "@" + domain
}

func setAccessTokenCookie(c echo.Context, expiresIn time.Duration, userID uint64, secret string) error {
	accessToken, err := cryptoutil.GenerateJWT(userID, expiresIn, secret)
	if err != nil {
		return err
	}
	cookie := http.Cookie{
		Name:     "accessToken",
		Value:    accessToken,
		MaxAge:   int(expiresIn.Seconds()),
		Path:     "/",
		SameSite: http.SameSiteNoneMode,
		HttpOnly: true,
		Secure:   true,
	}
	c.SetCookie(&cookie)
	return nil
}

func setRefreshTokenCookie(c echo.Context, expiresIn time.Duration, userID uint64, secret string) error {
	refreshToken, err := cryptoutil.GenerateJWT(userID, expiresIn, secret)
	if err != nil {
		return err
	}
	cookie := http.Cookie{
		Name:     "refreshToken",
		Value:    refreshToken,
		MaxAge:   int(expiresIn.Seconds()),
		Path:     "/auth/access-token",
		SameSite: http.SameSiteNoneMode,
		HttpOnly: true,
		Secure:   true,
	}
	c.SetCookie(&cookie)
	return nil
}

func clearAuthCookies(c echo.Context) {
	c.SetCookie(&http.Cookie{
		Name:     "accessToken",
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		SameSite: http.SameSiteNoneMode,
		HttpOnly: true,
		Secure:   true,
	})
	c.SetCookie(&http.Cookie{
		Name:     "refreshToken",
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		SameSite: http.SameSiteNoneMode,
		HttpOnly: true,
		Secure:   true,
	})
}

// This is a token bucket rate limiter. It does not enforce strict rate limiting but it's good enough for use as second level of defense at application level.
func rateLimiter(isEnabled bool) func(reqs int, window time.Duration) echo.MiddlewareFunc {
	// 'reqs' is the max number of requests allowed in 'window' time window.
	return func(reqs int, window time.Duration) echo.MiddlewareFunc {
		store := middleware.NewRateLimiterMemoryStoreWithConfig(middleware.RateLimiterMemoryStoreConfig{
			Rate:  rate.Every(window / time.Duration(reqs)),
			Burst: reqs,
		})
		if !isEnabled {
			store = middleware.NewRateLimiterMemoryStore(rate.Inf)
		}

		rc := middleware.DefaultRateLimiterConfig
		rc.Store = store
		rc.DenyHandler = func(c echo.Context, id string, err error) error {
			return echo.NewHTTPError(http.StatusTooManyRequests, MsgTooManyRequests)
		}
		rc.ErrorHandler = func(c echo.Context, err error) error {
			return err
		}

		return middleware.RateLimiterWithConfig(rc)
	}
}
