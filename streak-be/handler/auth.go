package handler

import (
	"fmt"
	"net/http"
	"net/url"
	"slices"

	"github.com/labstack/echo/v4"
	"github.com/rohitxdev/go-api-starter/cryptoutil"
	"github.com/rohitxdev/go-api-starter/email"
	"github.com/rohitxdev/go-api-starter/repo"
)

// @Summary Sign up
// @Tags Auth
// @Accept json
// @Produce json
// @Param email formData string true "Email"
// @Param password formData string true "Password"
// @Success 200 {object} Response
// @Router /auth/sign-up [post]
func (h *Handler) SignUp(c echo.Context) error {
	var req struct {
		Email    string `form:"email" json:"email" validate:"required,email"`
		Password string `form:"password" json:"password" validate:"required,min=8,max=128"`
	}
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}
	req.Email = canonicalizeEmail(req.Email)

	var userID uint64
	_, err := h.Repo.GetUserByEmail(c.Request().Context(), req.Email)
	if err == nil {
		return echo.NewHTTPError(http.StatusBadRequest, MsgUserAlreadyExists)
	}

	passwordHash, err := cryptoutil.HashSecure(req.Password)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	if userID, err = h.Repo.CreateUser(c.Request().Context(), req.Email, passwordHash); err != nil {
		switch err {
		case repo.ErrUserAlreadyExists:
			return echo.NewHTTPError(http.StatusBadRequest, MsgUserAlreadyExists)
		default:
			return fmt.Errorf("failed to create user: %w", err)
		}
	}

	if err = setAccessTokenCookie(c, h.Config.AccessTokenExpiresIn, userID, h.Config.AccessTokenSecret); err != nil {
		return fmt.Errorf("failed to set access token cookie: %w", err)
	}
	if err = setRefreshTokenCookie(c, h.Config.RefreshTokenExpiresIn, userID, h.Config.RefreshTokenSecret); err != nil {
		return fmt.Errorf("failed to set refresh token cookie: %w", err)
	}
	return c.JSON(http.StatusOK, Response{Message: "Signed up successfully", Success: true})
}

// @Summary Log in
// @Tags Auth
// @Accept json
// @Produce json
// @Param email formData string true "Email"
// @Param password formData string true "Password"
// @Success 200 {object} Response
// @Router /auth/log-in [post]
func (h *Handler) LogIn(c echo.Context) error {
	var req struct {
		Email    string `form:"email" json:"email" validate:"required,email"`
		Password string `form:"password" json:"password" validate:"required,min=8,max=128"`
	}
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}
	req.Email = canonicalizeEmail(req.Email)

	user, err := h.Repo.GetUserByEmail(c.Request().Context(), req.Email)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, MsgUserNotFound)
	}
	if user.AccountStatus != repo.AccountStatusActive {
		return echo.NewHTTPError(http.StatusForbidden, MsgAccountStatusNotActive)
	}

	if !cryptoutil.VerifyHashSecure(req.Password, user.PasswordHash) {
		return echo.NewHTTPError(http.StatusUnauthorized, MsgIncorrectPassword)
	}

	if err = setAccessTokenCookie(c, h.Config.AccessTokenExpiresIn, user.ID, h.Config.AccessTokenSecret); err != nil {
		return fmt.Errorf("failed to set access token cookie: %w", err)
	}
	if err = setRefreshTokenCookie(c, h.Config.RefreshTokenExpiresIn, user.ID, h.Config.RefreshTokenSecret); err != nil {
		return fmt.Errorf("failed to set refresh token cookie: %w", err)
	}
	return c.JSON(http.StatusOK, Response{Message: "Logged in successfully", Success: true})
}

// @Summary Log out
// @Tags Auth
// @Accept json
// @Produce json
// @Success 200 {object} Response
// @Router /auth/log-out [get]
func (h *Handler) LogOut(c echo.Context) error {
	_, err := c.Cookie("refreshToken")
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, MsgUserNotLoggedIn)
	}
	clearAuthCookies(c)
	return c.JSON(http.StatusOK, Response{Message: "Logged out successfully", Success: true})
}

// @Summary Get access token
// @Tags Auth
// @Accept json
// @Produce json
// @Success 200 {object} Response
// @Router /auth/access-token [get]
func (h *Handler) AccessToken(c echo.Context) error {
	refreshToken, err := c.Cookie("refreshToken")
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, MsgUserNotLoggedIn)
	}
	defer func() {
		if err != nil {
			clearAuthCookies(c)
		}
	}()

	userID, err := cryptoutil.VerifyJWT[uint64](refreshToken.Value, h.Config.RefreshTokenSecret)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, MsgJWTVerificationFailed)
	}

	user, err := h.Repo.GetUserById(c.Request().Context(), userID)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, MsgUserNotFound)
	}
	if user.AccountStatus != repo.AccountStatusActive {
		return echo.NewHTTPError(http.StatusForbidden, MsgAccountStatusNotActive)
	}

	if err = setAccessTokenCookie(c, h.Config.AccessTokenExpiresIn, user.ID, h.Config.AccessTokenSecret); err != nil {
		return fmt.Errorf("failed to set access token cookie: %w", err)
	}
	return c.JSON(http.StatusOK, Response{Message: "Generated access token successfully", Success: true})
}

// @Summary Update password
// @Tags Auth
// @Accept json
// @Produce json
// @Param currentPassword formData string true "Current password"
// @Param newPassword formData string true "New password"
// @Success 200 {object} Response
// @Router /auth/password [put]
func (h *Handler) UpdatePassword(c echo.Context) error {
	user, err := h.checkAuth(c, RoleUser)
	if err != nil {
		return err
	}
	var req struct {
		CurrentPassword string `form:"currentPassword" json:"currentPassword" validate:"required"`
		NewPassword     string `form:"newPassword" json:"newPassword" validate:"required,min=8,max=128"`
	}
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}

	if !cryptoutil.VerifyHashSecure(req.CurrentPassword, user.PasswordHash) {
		return echo.NewHTTPError(http.StatusUnauthorized, MsgIncorrectPassword)
	}
	if err := h.Repo.SetUserPassword(c.Request().Context(), user.ID, req.NewPassword); err != nil {
		return fmt.Errorf("failed to set user password: %w", err)
	}
	return c.JSON(http.StatusOK, Response{Message: "Password updated successfully", Success: true})
}

// @Summary Send reset password email
// @Tags Auth
// @Accept json
// @Produce json
// @Param email formData string true "Email"
// @Param callbackUrl formData string true "Callback URL"
// @Success 200 {object} Response
// @Router /auth/password/reset [post]
func (h *Handler) SendResetPasswordEmail(c echo.Context) error {
	var req struct {
		Email       string `form:"email" json:"email" validate:"required,email"`
		CallbackURL string `form:"callbackUrl" json:"callbackUrl" validate:"required"`
	}
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}

	user, err := h.Repo.GetUserByEmail(c.Request().Context(), canonicalizeEmail(req.Email))
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, MsgUserNotFound)
	}
	resetToken, err := cryptoutil.GenerateJWT(user.ID, h.Config.CommonTokenExpiresIn, h.Config.CommonTokenSecret)
	if err != nil {
		return fmt.Errorf("failed to generate password reset token: %w", err)
	}

	callbackURL, err := url.Parse(req.CallbackURL)
	if err != nil {
		return fmt.Errorf("failed to parse callback URL: %w", err)
	}

	if !h.Config.IsDev && !slices.Contains(h.Config.AllowedOrigins, callbackURL.Hostname()) {
		return echo.NewHTTPError(http.StatusBadRequest, MsgUnauthorizedCallbackURL)
	}

	query := callbackURL.Query()
	query.Add("token", resetToken)
	callbackURL.RawQuery = query.Encode()

	emailOpts := email.BaseOpts{
		Subject:     "Reset your password",
		FromAddress: h.Config.SenderEmail,
		FromName:    h.Config.AppName,
		ToAddresses: []string{req.Email},
		NoStack:     true,
	}
	data := map[string]any{
		"callbackURL":  callbackURL.String(),
		"validMinutes": h.Config.CommonTokenExpiresIn.Minutes(),
	}
	if err = h.Email.SendHTML(&emailOpts, "reset-password", data); err != nil {
		return fmt.Errorf("failed to send password reset email: %w", err)
	}
	return c.JSON(http.StatusOK, Response{Message: "Sent password reset email successfully", Success: true})
}

// @Summary Reset password
// @Tags Auth
// @Accept json
// @Produce json
// @Param token formData string true "Token"
// @Param newPassword formData string true "New password"
// @Success 200 {object} Response
// @Router /auth/password/reset [put]
func (h *Handler) ResetPassword(c echo.Context) error {
	var req struct {
		Token       string `form:"token" json:"token" validate:"required"`
		NewPassword string `form:"newPassword" json:"newPassword" validate:"required,min=8,max=128"`
	}
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}

	userID, err := cryptoutil.VerifyJWT[uint64](req.Token, h.Config.CommonTokenSecret)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, MsgJWTVerificationFailed)
	}
	if _, err = h.Repo.GetUserById(c.Request().Context(), userID); err != nil {
		return echo.NewHTTPError(http.StatusNotFound, MsgUserNotFound)
	}
	passwordHash, err := cryptoutil.HashSecure(req.NewPassword)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}
	if err = h.Repo.SetUserPassword(c.Request().Context(), userID, passwordHash); err != nil {
		return fmt.Errorf("failed to set user password: %w", err)
	}
	return c.JSON(http.StatusOK, Response{Message: "Password updated successfully", Success: true})
}

// @Summary Send account verification email
// @Tags Auth
// @Accept json
// @Produce json
// @Param email formData string true "Email"
// @Param callbackUrl formData string true "Callback URL"
// @Success 200 {object} Response
// @Router /auth/verify/email [post]
func (h *Handler) SendAccountVerificationEmail(c echo.Context) error {
	var req struct {
		Email       string `form:"email" json:"email" validate:"required,email"`
		CallbackURL string `form:"callbackUrl" json:"callbackUrl" validate:"required"`
	}
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}

	user, err := h.Repo.GetUserByEmail(c.Request().Context(), canonicalizeEmail(req.Email))
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, MsgUserNotFound)
	}
	if user.AccountStatus != repo.AccountStatusPending {
		return echo.NewHTTPError(http.StatusBadRequest, MsgAccountStatusNotPending)
	}
	verificationToken, err := cryptoutil.GenerateJWT(user.ID, h.Config.CommonTokenExpiresIn, h.Config.CommonTokenSecret)
	if err != nil {
		return fmt.Errorf("failed to generate account verification token: %w", err)
	}

	callbackURL, err := url.Parse(req.CallbackURL)
	if err != nil {
		return fmt.Errorf("failed to parse callback URL: %w", err)
	}

	if !h.Config.IsDev && !slices.Contains(h.Config.AllowedOrigins, callbackURL.Hostname()) {
		return echo.NewHTTPError(http.StatusBadRequest, MsgUnauthorizedCallbackURL)
	}

	query := callbackURL.Query()
	query.Add("token", verificationToken)
	callbackURL.RawQuery = query.Encode()

	emailOpts := email.BaseOpts{
		Subject:     "Verify your account",
		FromAddress: h.Config.SenderEmail,
		FromName:    h.Config.AppName,
		ToAddresses: []string{req.Email},
		NoStack:     true,
	}
	data := map[string]any{
		"callbackURL":  callbackURL.String(),
		"validMinutes": h.Config.CommonTokenExpiresIn.Minutes(),
	}
	if err = h.Email.SendHTML(&emailOpts, "verify-account", data); err != nil {
		return fmt.Errorf("failed to send account verification email: %w", err)
	}
	return c.JSON(http.StatusOK, Response{Message: "Sent verification email successfully", Success: true})
}

// @Summary Verify email
// @Tags Auth
// @Accept json
// @Produce json
// @Param token formData string true "Token"
// @Success 200 {object} Response
// @Router /auth/verify/email [put]
func (h *Handler) VerifyEmail(c echo.Context) error {
	var req struct {
		Token string `form:"token" json:"token" validate:"required"`
	}
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}

	userID, err := cryptoutil.VerifyJWT[uint64](req.Token, h.Config.CommonTokenSecret)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, MsgJWTVerificationFailed)
	}
	user, err := h.Repo.GetUserById(c.Request().Context(), userID)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, MsgUserNotFound)
	}
	if user.AccountStatus != repo.AccountStatusPending {
		return echo.NewHTTPError(http.StatusBadRequest, MsgAccountStatusNotPending)
	}
	if err = h.Repo.SetAccountStatusActive(c.Request().Context(), user.ID); err != nil {
		return fmt.Errorf("failed to set account status to active: %w", err)
	}
	return c.JSON(http.StatusOK, Response{Message: "Email verified successfully", Success: true})
}

// @Summary Delete user
// @Tags Auth
// @Accept json
// @Produce json
// @Success 200 {object} Response
// @Router /auth/user [delete]
func (h *Handler) DeleteUser(c echo.Context) error {
	user, err := h.checkAuth(c, RoleUser)
	if err != nil {
		return err
	}
	if err = h.Repo.DeleteUser(c.Request().Context(), user.ID); err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	return c.JSON(http.StatusOK, Response{Message: "User deleted successfully", Success: true})
}

// @Summary Get current user
// @Tags Auth
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Success 200 {object} ResponseWithPayload[repo.PublicUser]
// @Router /auth/user [get]
func (h *Handler) User(c echo.Context) error {
	user, err := h.checkAuth(c, RoleUser)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, ResponseWithPayload[repo.PublicUser]{
		Message: "Fetched current user successfully",
		Success: true,
		Payload: repo.PublicUser{
			ID:          user.ID,
			Role:        user.Role,
			Email:       user.Email,
			Username:    user.Username,
			ImageURL:    user.ImageURL,
			Gender:      user.Gender,
			DateOfBirth: user.DateOfBirth,
			CreatedAt:   user.CreatedAt,
			UpdatedAt:   user.UpdatedAt,
		},
	})
}
