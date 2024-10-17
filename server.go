package main

import (
	"fmt"

	fiber "github.com/gofiber/fiber/v2"
)

func main() {
	app := fiber.New()
	app.Static("/files", "./resources")
	app.Static("/", "./resources/index.html")
	app.Post("/button-click", Button)
	app.Listen(":8080")
}

func Button(c *fiber.Ctx) error {
	fmt.Println(c.Context())
	return c.JSON(fiber.Map{"message": "Button click received"})
}
