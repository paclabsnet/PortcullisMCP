package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/paclabsnet/PortcullisMCP/internal/keep"
	"github.com/paclabsnet/PortcullisMCP/internal/version"
)

func main() {
	cfgPath := flag.String("config", "/etc/portcullis/keep.yaml", "path to keep config file")
	flag.Parse()

	slog.Info("portcullis-keep starting", "version", version.Version)

	cfg, err := keep.LoadConfig(*cfgPath)
	if err != nil {
		slog.Error("load config", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	srv, err := keep.NewServer(cfg, *cfgPath)
	if err != nil {
		slog.Error("init keep", "error", err)
		os.Exit(1)
	}

	if err := srv.Run(ctx); err != nil && err != context.Canceled {
		slog.Error("keep exited", "error", err)
		os.Exit(1)
	}
}

