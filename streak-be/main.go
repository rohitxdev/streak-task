//go:generate go run github.com/swaggo/swag/cmd/swag@latest init -q -g handler/routes.go
package main

import (
	"github.com/rohitxdev/go-api-starter/app"
)

func main() {
	if err := app.Run(); err != nil {
		panic(err)
	}
}
