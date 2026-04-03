// Copyright 2026 Policy-as-Code Laboratories (PAC.Labs)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/paclabsnet/PortcullisMCP/internal/keep"
	cfgloader "github.com/paclabsnet/PortcullisMCP/internal/shared/config"
	"github.com/paclabsnet/PortcullisMCP/internal/telemetry"
	"github.com/paclabsnet/PortcullisMCP/internal/version"
)

// logSetupFn is the logging-setup function. Overridable in tests.
var logSetupFn = cfgloader.SetupLogging

type cliArgs struct {
	config   string
	logLevel string
}

// parseFlags parses argv using a fresh FlagSet so it can be called in tests
// without touching flag.CommandLine or calling os.Exit.
func parseFlags(argv []string) (cliArgs, error) {
	fs := flag.NewFlagSet("portcullis-keep", flag.ContinueOnError)
	var a cliArgs
	fs.StringVar(&a.config, "config", "/etc/portcullis/keep.yaml", "path to keep config file")
	fs.StringVar(&a.logLevel, "log-level", "", "override logging level (debug, info, warn, error)")
	return a, fs.Parse(argv)
}

// applyLogging calls logSetupFn with the loaded config and parsed CLI args.
// It is the only call site that forwards args.logLevel into the logging setup,
// which makes the forwarding path directly testable.
func applyLogging(cfg keep.Config, args cliArgs) error {
	return logSetupFn(cfg.Operations.Logging, cfg.Mode, args.logLevel)
}

func main() {
	cfgloader.BootstrapLogger()

	args, err := parseFlags(os.Args[1:])
	if err == flag.ErrHelp {
		os.Exit(0)
	}
	if err != nil {
		os.Exit(2) // flag package already wrote the error to stderr
	}

	slog.Info("portcullis-keep starting", "version", version.Version)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg, err := keep.LoadConfig(ctx, args.config)
	if err != nil {
		slog.Error("load config", "error", err)
		os.Exit(1)
	}

	if err := applyLogging(cfg, args); err != nil {
		slog.Error("invalid log level", "error", err)
		os.Exit(1)
	}

	shutdownTelemetry, err := telemetry.Setup(ctx, cfg.Operations.Telemetry)
	if err != nil {
		slog.Error("init telemetry", "error", err)
		os.Exit(1)
	}
	defer func() { _ = shutdownTelemetry(context.Background()) }()

	srv, err := keep.NewServer(ctx, cfg, args.config)
	if err != nil {
		slog.Error("init keep", "error", err)
		os.Exit(1)
	}

	if err := srv.Run(ctx); err != nil && err != context.Canceled {
		slog.Error("keep exited", "error", err)
		os.Exit(1)
	}
}
