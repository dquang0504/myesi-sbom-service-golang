package main

import (
	"context"
	"log"
	_ "myesi-sbom-service-golang/docs" // <— import docs package
	v1 "myesi-sbom-service-golang/internal/api/v1"
	"myesi-sbom-service-golang/internal/config"
	"myesi-sbom-service-golang/internal/db"
	"myesi-sbom-service-golang/internal/services"
	"os"
	"os/signal"
	"syscall"
	"time"

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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	app := fiber.New(fiber.Config{BodyLimit: 25 * 1024 * 1024})
	api := app.Group("/api")

	sbomGroup := api.Group("/sbom")
	v1.RegisterSBOMRoutes(sbomGroup)

	projectsGroup := api.Group("/projects")
	v1.RegisterProjectRoutes(projectsGroup)

	services.StartCodeScanConsumer(ctx)
	services.StartOutboxDispatcher(ctx)

	app.Get("/swagger/*", fiberSwagger.HandlerDefault) // Swagger UI endpoint
	log.Println("SBOM service listening on port 8002")

	errCh := make(chan error, 1)
	go func() {
		if err := app.Listen(":8002"); err != nil {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	log.Println("[STARTUP] SBOM Service running...")

	select {
	case <-ctx.Done():
		log.Println("[SHUTDOWN] signal received, shutting down...")
	case err := <-errCh:
		if err != nil {
			log.Printf("[SHUTDOWN] Fiber server error: %v", err)
		}
	}

	_, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := app.Shutdown(); err != nil {
		log.Printf("[SHUTDOWN][ERR] Fiber shutdown: %v", err)
	}

	db.CloseDB()
	services.CloseKafkaWriters()

	log.Println("[EXIT] SBOM Service stopped gracefully")
}
