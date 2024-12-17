package handler

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

// @Summary Home page
// @Success 200 {html} string "Home page"
// @Router / [get]
func (h *Handler) Home(c echo.Context) error {
	return c.Render(http.StatusOK, "home", echo.Map{
		"appName":    h.Config.AppName,
		"appVersion": h.Config.AppVersion,
	})
}

type ClientConfig struct {
	Env        string `json:"env"`
	AppName    string `json:"appName"`
	AppVersion string `json:"appVersion"`
}

// @Summary Get client config
// @Success 200 {object} ResponseWithPayload[ClientConfig]
// @Router /config [get]
func (h *Handler) ClientConfig(c echo.Context) error {
	return c.JSON(http.StatusOK, ResponseWithPayload[ClientConfig]{
		Message: "Fetched config successfully",
		Success: true,
		Payload: ClientConfig{
			Env:        h.Config.Env,
			AppName:    h.Config.AppName,
			AppVersion: h.Config.AppVersion,
		},
	})
}
