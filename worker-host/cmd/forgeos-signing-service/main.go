package main

import (
	"context"
		"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/michaelkage/ForgeOS/worker-host/internal/signing"
)

func main(){
	cfg,err:=signing.ConfigFromEnv();if err!=nil{log.Fatal(err)}
	service,err:=signing.NewService(cfg);if err!=nil{log.Fatal(err)}
	ctx,stop:=signal.NotifyContext(context.Background(),os.Interrupt,syscall.SIGTERM);defer stop()
	if err:=service.Serve(ctx);err!=nil{log.Fatal(err)}
}
