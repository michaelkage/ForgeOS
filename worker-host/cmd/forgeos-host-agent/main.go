//go:build linux

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/michaelkage/ForgeOS/worker-host/internal/agent"
)

func main() {
	if err:=run();err!=nil{log.Fatal(err)}
}

func run()error{
	if os.Geteuid()!=0{return errors.New("forgeos-host-agent must run as root")}
	configPath:=os.Getenv("HOST_AGENT_CONFIG")
	if configPath==""{return errors.New("HOST_AGENT_CONFIG is required")}
	configData,err:=readRootOwned(configPath,1<<20);if err!=nil{return fmt.Errorf("read host-agent config: %w",err)}
	var linuxConfig agent.LinuxConfig
	if err:=json.Unmarshal(configData,&linuxConfig);err!=nil{return fmt.Errorf("decode host-agent config: %w",err)}
	token:=os.Getenv("HOST_AGENT_TOKEN");if len(token)<32{return errors.New("HOST_AGENT_TOKEN must contain at least 32 bytes")}
	keyPath:=os.Getenv("HOST_AGENT_SIGNING_KEY")
	if keyPath==""{return errors.New("HOST_AGENT_SIGNING_KEY is required")}
	keyPEM,err:=readRootOwned(keyPath,16*1024);if err!=nil{return err}
	block,_:=pem.Decode(keyPEM);if block==nil{return errors.New("host-agent signing key is not valid PEM")}
	parsed,err:=x509.ParsePKCS8PrivateKey(block.Bytes);if err!=nil{return fmt.Errorf("parse host-agent signing key: %w",err)}
	privateKey,ok:=parsed.(ed25519.PrivateKey);if !ok{return errors.New("host-agent signing key must be Ed25519")}
	linuxConfig.SigningKey=privateKey
	runtime,err:=agent.NewLinuxRuntime(linuxConfig);if err!=nil{return err}
	if err:=runtime.Recover();err!=nil{return fmt.Errorf("fail-closed recovery of previous VMs: %w",err)}
	server,err:=agent.NewServer(agent.Config{BearerToken:token,SigningKey:privateKey,StateDir:linuxConfig.StateDir,Runtime:runtime});if err!=nil{return err}
	cert:=os.Getenv("HOST_AGENT_TLS_CERT");key:=os.Getenv("HOST_AGENT_TLS_KEY")
	if cert==""||key==""{return errors.New("HOST_AGENT_TLS_CERT and HOST_AGENT_TLS_KEY are required")}
	if _,err:=readRootOwned(cert,1<<20);err!=nil{return err};if _,err:=readRootOwned(key,1<<20);err!=nil{return err}
	listen:=os.Getenv("HOST_AGENT_LISTEN");if listen==""{listen=":9443"}
	httpServer:=&http.Server{Addr:listen,Handler:server.Handler(),ReadHeaderTimeout:5*time.Second,ReadTimeout:15*time.Second,WriteTimeout:20*time.Second,IdleTimeout:30*time.Second,MaxHeaderBytes:16*1024,TLSConfig:&tls.Config{MinVersion:tls.VersionTLS13}}
	ctx,stop:=signal.NotifyContext(context.Background(),syscall.SIGINT,syscall.SIGTERM);defer stop()
	go func(){ticker:=time.NewTicker(time.Second);defer ticker.Stop();for{select{case<-ctx.Done():return;case<-ticker.C:if err:=runtime.SweepExpired();err!=nil{log.Printf("host-agent expiry reaper failed: %v",err)}}}}()
	errCh:=make(chan error,1)
	go func(){errCh<-httpServer.ListenAndServeTLS(cert,key)}()
	select{
	case <-ctx.Done():
		shutdownCtx,cancel:=context.WithTimeout(context.Background(),15*time.Second);defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
		if err:=runtime.Recover();err!=nil{return fmt.Errorf("VM teardown during shutdown failed: %w",err)}
		return nil
	case err:=<-errCh:
		if errors.Is(err,http.ErrServerClosed){return nil}
		return err
	}
}

func readRootOwned(path string,max int64)([]byte,error){
	if !filepath.IsAbs(path){return nil,errors.New("security-sensitive file paths must be absolute")}
	st,err:=os.Lstat(path);if err!=nil{return nil,err}
	if !st.Mode().IsRegular()||st.Mode()&os.ModeSymlink!=0{return nil,errors.New("security-sensitive file must be a regular non-symlink file")}
	sys,ok:=st.Sys().(*syscall.Stat_t);if !ok||sys.Uid!=0||st.Mode().Perm()&0077!=0{return nil,errors.New("security-sensitive file must be root-owned and mode 0600 or stricter")}
	if st.Size()>max{return nil,errors.New("security-sensitive file exceeds size limit")}
	return os.ReadFile(path)
}
