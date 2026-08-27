// Command onetime is the one-time secret sharing service.
//
// Subcommands:
//
//	serve        run the HTTP server (default)
//	healthcheck  probe the local server and exit non-zero if it is unwell
//	gc           run a garbage collection pass and exit
//	keygen       print a fresh master keyring entry
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

// Stamped at build time via -ldflags.
var (
	version   = "dev"
	commit    = "none"
	buildDate = "unknown"
)

func main() {
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var err error
	switch cmd {
	case "serve":
		err = runServe(ctx)
	case "healthcheck":
		err = runHealthcheck()
	case "gc":
		err = runGC(ctx)
	case "keygen":
		err = runKeygen()
	case "version", "-v", "--version":
		fmt.Printf("onetime %s (%s, built %s)\n", version, commit, buildDate)
		return
	case "help", "-h", "--help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "onetime: unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}

	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(os.Stderr, "onetime: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `onetime - one-time secret sharing

Usage: onetime [command]

Commands:
  serve        run the HTTP server (default)
  healthcheck  probe the local server; exits non-zero when unhealthy
  gc           run one garbage collection pass and exit
  keygen       print a new master keyring entry
  version      print build information

Configuration is read from ONETIME_* environment variables.
See docs/llms.txt and the Helm chart values for the full list.
`)
}
