package main

import (
	"context"
	"log"
	"log/slog"

	"dproxy-server-go/internal/server"
)

func main() {
	args, err := server.LoadConfig()
	if err != nil {
		log.Fatal(err)
	}

	slog.SetLogLoggerLevel(args.Logging.Level)

	s, err := server.New(args)
	if err != nil {
		log.Fatal(err)
	}

	err = s.Start(context.Background())
	if err != nil {
		log.Fatal(err)
	}
}
