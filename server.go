package main

import (
	"fmt"

	fiber "github.com/gofiber/fiber/v2"
)

func main() {
	app := fiber.New()
	app.Static("/files", "./resources")
	app.Static("/", "./resources/index.html")
	app.Get("/button-click", Button)
	app.Listen(":8080")
}

func Button(c *fiber.Ctx) error {
	fmt.Println("Knopka")
	return c.JSON(fiber.Map{"message": "Button click received"})
}
