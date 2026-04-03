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

	"github.com/paclabsnet/PortcullisMCP/internal/gate"
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
	fs := flag.NewFlagSet("portcullis-gate", flag.ContinueOnError)
	var a cliArgs
	fs.StringVar(&a.config, "config", "~/.portcullis/gate.yaml", "path to gate config file")
	fs.StringVar(&a.logLevel, "log-level", "", "override logging level (debug, info, warn, error)")
	return a, fs.Parse(argv)
}

// applyLogging calls logSetupFn with the loaded config and parsed CLI args.
// It is the only call site that forwards args.logLevel into the logging setup,
// which makes the forwarding path directly testable.
func applyLogging(cfg gate.Config, args cliArgs) error {
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

	slog.Info("portcullis-gate starting", "version", version.Version)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg, report, err := gate.LoadConfig(ctx, args.config)
	if err != nil {
		slog.Error("load config", "error", err)
		runDegraded(ctx, "configuration error: "+err.Error())
		return
	}

	if err := applyLogging(cfg, args); err != nil {
		slog.Error("invalid log level", "error", err)
		runDegraded(ctx, "invalid log level: "+err.Error())
		return
	}

	report.Log("portcullis-gate")

	shutdownTelemetry, err := telemetry.Setup(ctx, cfg.Operations.Telemetry)
	if err != nil {
		slog.Error("init telemetry", "error", err)
		// Telemetry is non-critical infrastructure; log and continue without it.
		shutdownTelemetry = func(_ context.Context) error { return nil }
	}
	defer func() { _ = shutdownTelemetry(context.Background()) }()

	g, err := gate.New(ctx, cfg)
	if err != nil {
		slog.Error("init gate", "error", err)
		runDegraded(ctx, err.Error())
		return
	}

	if err := g.Run(ctx); err != nil && err != context.Canceled {
		slog.Error("gate exited", "error", err)
		os.Exit(1)
	}
}

// runDegraded starts Gate in degraded mode and exits when the MCP session ends.
// Startup errors are surfaced to the MCP agent via a portcullis_status pseudo-tool.
func runDegraded(ctx context.Context, reason string) {
	if err := gate.RunDegraded(ctx, reason); err != nil && err != context.Canceled {
		slog.Error("degraded gate exited with error", "error", err)
		os.Exit(1)
	}
}
