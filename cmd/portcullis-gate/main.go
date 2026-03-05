package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"gopkg.in/yaml.v3"

	"github.com/paclabsnet/PortcullisMCP/internal/gate"
	"github.com/paclabsnet/PortcullisMCP/internal/shared"
)

func main() {
	cfgPath := flag.String("config", "~/.portcullis/gate.yaml", "path to gate config file")
	flag.Parse()

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		slog.Error("load config", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	g, err := gate.New(ctx, cfg)
	if err != nil {
		slog.Error("init gate", "error", err)
		os.Exit(1)
	}

	if err := g.Run(ctx); err != nil && err != context.Canceled {
		slog.Error("gate exited", "error", err)
		os.Exit(1)
	}
}

func loadConfig(path string) (gate.Config, error) {
	expanded, err := expandHome(path)
	if err != nil {
		return gate.Config{}, err
	}
	data, err := os.ReadFile(expanded)
	if err != nil {
		return gate.Config{}, err
	}
	// Expand environment variables in the YAML
	data = shared.ExpandEnvVarsInYAML(data)
	var cfg gate.Config
	return cfg, yaml.Unmarshal(data, &cfg)
}

func expandHome(path string) (string, error) {
	if len(path) == 0 || path[0] != '~' {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return home + path[1:], nil
}
