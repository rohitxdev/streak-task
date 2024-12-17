package handler

import (
	"fmt"
	"math"
	"net"
	"net/http"
	"time"

	"github.com/labstack/echo-contrib/echoprometheus"
	"github.com/labstack/echo/v4"
	"github.com/rohitxdev/go-api-starter/docs"
	echoSwagger "github.com/swaggo/echo-swagger"
)

// @title Go API Starter
// @version 1.0.0
// @description Go API Starter is a boilerplate for building RESTful APIs in Go.
// @BasePath /
func mountRoutes(e *echo.Echo, h *Handler) {
	docs.SwaggerInfo.Host = net.JoinHostPort(h.Config.Host, h.Config.Port)
	limit := rateLimiter(!h.Config.IsDev)

	e.Pre(limit(100, time.Minute))
	e.GET("/metrics", echoprometheus.NewHandler())
	e.GET("/swagger/*", echoSwagger.EchoWrapHandler())
	e.GET("/config", h.ClientConfig)
	e.GET("/", h.Home)

	auth := e.Group("/auth")
	{
		auth.POST("/sign-up", h.SignUp)
		auth.POST("/log-in", h.LogIn)
		auth.GET("/log-out", h.LogOut)
		auth.GET("/access-token", h.AccessToken, limit(2, h.Config.AccessTokenExpiresIn))
		user := auth.Group("/user")
		{
			user.GET("", h.User)
			user.DELETE("", h.DeleteUser)
			password := user.Group("/password")
			{
				password.PUT("", h.UpdatePassword)
				password.POST("/reset", h.SendResetPasswordEmail, limit(2, time.Minute))
				password.PUT("/reset", h.ResetPassword)
			}
		}
		verification := auth.Group("/verify")
		{
			verification.POST("/email", h.SendAccountVerificationEmail, limit(2, time.Minute))
			verification.PUT("/email", h.VerifyEmail)
		}
	}

	e.POST("/find-path", func(c echo.Context) error {

		var req struct {
			Start Coords `json:"start"`
			End   Coords `json:"end"`
		}
		if err := bindAndValidate(c, &req); err != nil {
			return err
		}
		return c.JSON(http.StatusOK, calculatePath(req.Start, req.End))
	})
}

type Coords struct {
	X int `json:"x"`
	Y int `json:"y"`
}

func calculatePath(start Coords, end Coords) []Coords {
	// xSize := int(math.Abs(float64(end.X)-float64(start.X))) + 1
	// ySize := int(math.Abs(float64(end.Y)-float64(start.Y))) + 1
	minX := int(math.Min(float64(start.X), float64(end.X)))
	minY := int(math.Min(float64(start.Y), float64(end.Y)))
	maxX := int(math.Max(float64(start.X), float64(end.X)))
	maxY := int(math.Max(float64(start.Y), float64(end.Y)))
	// grid := make([]Coords, 0)
	// for i := range xSize {
	// 	for j := range ySize {
	// 		x := minX + i
	// 		y := minY + j
	// 		grid = append(grid, Coords{X: x, Y: y})
	// 	}
	// }
	fmt.Println(maxX, maxY)

	path := make([]Coords, 0)
	return dfs(start, end, minX, minY, maxX, maxY, path)
}

func dfs(current Coords, target Coords, minX int, minY int, maxX int, maxY int, path []Coords) []Coords {
	left := Coords{X: current.X - 1, Y: current.Y}
	right := Coords{X: current.X + 1, Y: current.Y}
	top := Coords{X: current.X, Y: current.Y - 1}
	bottom := Coords{X: current.X, Y: current.Y + 1}

	if current.X == target.X && current.Y == target.Y {
		path = append(path, current)
		return path
	}

	if right.X <= maxX {
		path = append(path, right)
		return dfs(right, target, minX, minY, maxX, maxY, path)
	}

	if bottom.Y <= maxY {
		path = append(path, bottom)
		return dfs(bottom, target, minX, minY, maxX, maxY, path)
	}

	if left.X >= minX {
		path = append(path, left)
		return dfs(left, target, minX, minY, maxX, maxY, path)
	}

	if top.Y >= minY {
		path = append(path, bottom)
		return dfs(bottom, target, minX, minY, maxX, maxY, path)
	}

	return path
}
