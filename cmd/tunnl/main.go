package main

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

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

	srv, err := server.New(cfg.HostKeyPath)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// Start SSH server
	sshListener, err := net.Listen("tcp", cfg.SSHAddr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", cfg.SSHAddr, err)
	}
	log.Printf("SSH server listening on %s", cfg.SSHAddr)

	go func() {
		for {
			conn, err := sshListener.Accept()
			if err != nil {
				log.Printf("Failed to accept SSH connection: %v", err)
				continue
			}
			go srv.HandleSSHConnection(conn)
		}
	}()

	// HTTP server for redirect
	httpServer := &http.Server{
		Addr:         cfg.HTTPAddr,
		Handler:      server.HTTPRedirectHandler(),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	// HTTPS server
	httpsServer := &http.Server{
		Addr:           cfg.HTTPSAddr,
		Handler:        srv,
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   30 * time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 << 20,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	log.Printf("HTTP server listening on %s (redirects to HTTPS)", cfg.HTTPAddr)
	go func() {
		if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	log.Printf("HTTPS server listening on %s", cfg.HTTPSAddr)
	go func() {
		if err := httpsServer.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey); err != http.ErrServerClosed {
			log.Fatalf("HTTPS server error: %v", err)
		}
	}()

	// Stats server (localhost only)
	statsServer := &http.Server{
		Addr:         cfg.StatsAddr,
		Handler:      srv.StatsHandler(),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
	log.Printf("Stats server listening on %s", cfg.StatsAddr)
	go func() {
		if err := statsServer.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("Stats server error: %v", err)
		}
	}()

	// Graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Println("Shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	httpServer.Shutdown(ctx)
	httpsServer.Shutdown(ctx)
	statsServer.Shutdown(ctx)
	sshListener.Close()
}
