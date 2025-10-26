package main

import (
	"context"
	"log"
	_ "myesi-sbom-service-golang/docs" // <— import docs package
	v1 "myesi-sbom-service-golang/internal/api/v1"
	"myesi-sbom-service-golang/internal/config"
	"myesi-sbom-service-golang/internal/db"
	"os"
	"os/signal"
	"syscall"

	fiber "github.com/gofiber/fiber/v2"
	fiberSwagger "github.com/gofiber/swagger"
)

// @title MyESI SBOM Service API
// @version 1.0
// @description API documentation for SBOM microservice
// @host localhost:8002
// @BasePath /api/sbom

func main() {
	cfg := config.LoadConfig()
	db.InitPostgres(cfg.DatabaseURL)

	app := fiber.New(fiber.Config{BodyLimit: 25 * 1024 * 1024})
	v1.RegisterSBOMRoutes(app)

	app.Get("/swagger/*", fiberSwagger.HandlerDefault) // Swagger UI endpoint
	log.Println("SBOM service listening on port 8002")
	app.Listen(":8002")

	//setup graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Println("[STARTUP] Vulnerability Service running...")

	//wait until shutdown
	<-ctx.Done()

	log.Println("[EXIT] Vulnerability stopped gracefully")
}
