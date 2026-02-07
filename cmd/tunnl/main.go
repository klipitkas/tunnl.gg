package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"tunnl.gg/internal/config"
	"tunnl.gg/internal/server"
)

func main() {
	cfg := config.Default()

	if v := os.Getenv("SSH_ADDR"); v != "" {
		cfg.SSHAddr = v
	}
	if v := os.Getenv("HTTP_ADDR"); v != "" {
		cfg.HTTPAddr = v
	}
	if v := os.Getenv("HTTPS_ADDR"); v != "" {
		cfg.HTTPSAddr = v
	}
	if v := os.Getenv("HOST_KEY_PATH"); v != "" {
		cfg.HostKeyPath = v
	}
	if v := os.Getenv("TLS_CERT"); v != "" {
		cfg.TLSCert = v
	}
	if v := os.Getenv("TLS_KEY"); v != "" {
		cfg.TLSKey = v
	}
	if v := os.Getenv("STATS_ADDR"); v != "" {
		cfg.StatsAddr = v
	}
	if v := os.Getenv("DOMAIN"); v != "" {
		cfg.Domain = v
	}

	srv, err := server.New(cfg.HostKeyPath, cfg.Domain)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// Start SSH server
	sshListener, err := net.Listen("tcp", cfg.SSHAddr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", cfg.SSHAddr, err)
	}
	log.Printf("SSH server listening on %s", cfg.SSHAddr)

	sshShutdown := make(chan struct{})
	sshDone := make(chan struct{})
	go func() {
		defer close(sshDone)
		for {
			conn, err := sshListener.Accept()
			if err != nil {
				// Check if shutdown was requested
				select {
				case <-sshShutdown:
					return
				default:
				}
				log.Printf("Failed to accept SSH connection: %v", err)
				continue
			}
			go srv.HandleSSHConnection(conn)
		}
	}()

	// HTTP server for redirect
	httpServer := &http.Server{
		Addr:         cfg.HTTPAddr,
		Handler:      srv.HTTPRedirectHandler(),
		ReadTimeout:  config.HTTPReadTimeout,
		WriteTimeout: config.HTTPWriteTimeout,
		IdleTimeout:  config.HTTPIdleTimeout,
	}

	// HTTPS server
	httpsServer := &http.Server{
		Addr:           cfg.HTTPSAddr,
		Handler:        srv,
		ReadTimeout:    config.HTTPSReadTimeout,
		WriteTimeout:   config.HTTPSWriteTimeout,
		IdleTimeout:    config.HTTPSIdleTimeout,
		MaxHeaderBytes: 1 << 20,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	// Stats server (localhost only)
	statsServer := &http.Server{
		Addr:         cfg.StatsAddr,
		Handler:      srv.StatsHandler(),
		ReadTimeout:  config.StatsReadTimeout,
		WriteTimeout: config.StatsWriteTimeout,
	}

	// Channel to signal fatal server errors
	serverErr := make(chan error, 3)

	log.Printf("HTTP server listening on %s (redirects to HTTPS)", cfg.HTTPAddr)
	go func() {
		if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
			serverErr <- fmt.Errorf("HTTP server error: %w", err)
		}
	}()

	log.Printf("HTTPS server listening on %s", cfg.HTTPSAddr)
	go func() {
		if err := httpsServer.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey); err != http.ErrServerClosed {
			serverErr <- fmt.Errorf("HTTPS server error: %w", err)
		}
	}()

	log.Printf("Stats server listening on %s", cfg.StatsAddr)
	go func() {
		if err := statsServer.ListenAndServe(); err != http.ErrServerClosed {
			serverErr <- fmt.Errorf("stats server error: %w", err)
		}
	}()

	// Wait for shutdown signal or fatal server error
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		log.Printf("Received signal %v, shutting down...", sig)
	case err := <-serverErr:
		log.Printf("Fatal error: %v, shutting down...", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), config.ShutdownTimeout)
	defer cancel()

	// Shutdown HTTP servers gracefully
	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("HTTP server shutdown error: %v", err)
	}
	if err := httpsServer.Shutdown(ctx); err != nil {
		log.Printf("HTTPS server shutdown error: %v", err)
	}
	if err := statsServer.Shutdown(ctx); err != nil {
		log.Printf("Stats server shutdown error: %v", err)
	}

	// Signal SSH goroutine to stop, then close listener
	close(sshShutdown)
	sshListener.Close()
	<-sshDone // Wait for SSH accept loop to finish

	srv.Stop()
	log.Println("Shutdown complete")
}
