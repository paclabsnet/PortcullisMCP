package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"gopkg.in/yaml.v3"

	"github.com/paclabsnet/PortcullisMCP/internal/guard"
	"github.com/paclabsnet/PortcullisMCP/internal/shared"
	"github.com/paclabsnet/PortcullisMCP/internal/version"
)

func main() {
	cfgPath := flag.String("config", "/etc/portcullis/guard.yaml", "path to guard config file")
	flag.Parse()

	slog.Info("portcullis-guard starting", "version", version.Version)

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		slog.Error("load config", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	srv, err := guard.NewServer(cfg)
	if err != nil {
		slog.Error("init guard", "error", err)
		os.Exit(1)
	}

	if err := srv.Run(ctx); err != nil && err != context.Canceled {
		slog.Error("guard exited", "error", err)
		os.Exit(1)
	}
}

func loadConfig(path string) (guard.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return guard.Config{}, err
	}
	data = shared.ExpandEnvVarsInYAML(data)
	var cfg guard.Config
	return cfg, yaml.Unmarshal(data, &cfg)
}
