package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"io/fs"

	"github.com/kingman4/better-esg/internal/config"
	"github.com/kingman4/better-esg/internal/logging"
	"github.com/kingman4/better-esg/internal/server"
	"github.com/kingman4/better-esg/web"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	logger := logging.New(cfg.LogLevel)

	srv, err := server.New(server.Config{
		DatabaseURL:        cfg.DatabaseURL,
		FDAExternalBaseURL: cfg.FDAExternalBaseURL,
		FDAUploadBaseURL:   cfg.FDAUploadBaseURL,
		FDAClientID:        cfg.FDAClientID,
		FDAClientSecret:    cfg.FDAClientSecret,
		FDAEnvironment:     cfg.FDAEnvironment,
		FDAUserEmail:       cfg.FDAUserEmail,
		EncryptionKey:      cfg.EncryptionKey,
		StatusPollInterval: cfg.StatusPollInterval,
		Logger:             logger,
		StorageBackend:     cfg.StorageBackend,
		StoragePath:        cfg.StoragePath,
		S3Bucket:           cfg.S3Bucket,
		S3Prefix:           cfg.S3Prefix,
		S3Region:           cfg.S3Region,
		S3Endpoint:         cfg.S3Endpoint,
		JWTSecret:          cfg.JWTSecret,
		AuthDisabled:       cfg.AuthDisabled,
		FDADebug:           cfg.FDADebug,
		StaticFS:           mustSubFS(web.StaticFS, "static"),
	})
	if err != nil {
		logger.Error("failed to create server", "error", err)
		os.Exit(1)
	}
	defer srv.Close()

	httpServer := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      srv,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)

	go func() {
		logger.Info("server listening", "port", cfg.Port)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	<-done
	logger.Info("shutting down")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		logger.Error("forced shutdown", "error", err)
		os.Exit(1)
	}

	logger.Info("server stopped")
}

func mustSubFS(fsys fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		log.Fatalf("failed to create sub filesystem for %q: %v", dir, err)
	}
	return sub
}
