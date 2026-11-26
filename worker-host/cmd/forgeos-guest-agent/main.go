//go:build linux

package main

import (
	"context"
	"errors"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/michaelkage/ForgeOS/worker-host/internal/guest"
)

func main(){
	if len(os.Args)>1&&os.Args[1]=="--worker-child"{if len(os.Args)<4{log.Fatal("invalid worker child invocation")};if err:=guest.ExecWorkerChild(os.Args[2],os.Args[3],os.Args[4:]);err!=nil{log.Fatal(err)};return}
	ctx,stop:=signal.NotifyContext(context.Background(),syscall.SIGINT,syscall.SIGTERM);defer stop()
	port:=uint64(4050);if raw:=os.Getenv("FORGEOS_VSOCK_PORT");raw!=""{v,e:=strconv.ParseUint(raw,10,32);if e!=nil{log.Fatal("invalid FORGEOS_VSOCK_PORT")};port=v}
	err:=guest.Run(ctx,guest.Config{PublicKeyPath:os.Getenv("FORGEOS_HOST_PUBLIC_KEY"),WorkerPath:os.Getenv("FORGEOS_BUILD_WORKER"),ArtifactPath:os.Getenv("FORGEOS_ARTIFACT_PATH"),VsockPort:uint32(port)})
	if err!=nil&&!errors.Is(err,context.Canceled){log.Fatal(err)}
}
