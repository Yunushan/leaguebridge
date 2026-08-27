package main

import (
	"context"
	"os"
	"os/signal"
)

import "github.com/Yunushan/leaguebridge/internal/app"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	application := app.New(os.Stdin, os.Stdout, os.Stderr)
	os.Exit(application.Run(ctx, os.Args[1:]))
}
