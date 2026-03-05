package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"gopkg.in/yaml.v3"

	"github.com/paclabsnet/PortcullisMCP/internal/keep"
	"github.com/paclabsnet/PortcullisMCP/internal/shared"
)

func main() {
	cfgPath := flag.String("config", "/etc/portcullis/keep.yaml", "path to keep config file")
	flag.Parse()

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		slog.Error("load config", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	srv, err := keep.NewServer(cfg)
	if err != nil {
		slog.Error("init keep", "error", err)
		os.Exit(1)
	}

	if err := srv.Run(ctx); err != nil && err != context.Canceled {
		slog.Error("keep exited", "error", err)
		os.Exit(1)
	}
}

func loadConfig(path string) (keep.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return keep.Config{}, err
	}
	// Expand environment variables in the YAML
	data = shared.ExpandEnvVarsInYAML(data)
	var cfg keep.Config
	return cfg, yaml.Unmarshal(data, &cfg)
}
