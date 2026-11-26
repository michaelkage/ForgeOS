package main

import (
	"context"
	"errors"
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
	done:=make(chan error,1);go func(){done<-service.Serve()}()
	select{case<-ctx.Done():log.Print("signing service shutdown requested");case err:=<-done:if err!=nil&&!errors.Is(err,context.Canceled){log.Fatal(err)}}
}
