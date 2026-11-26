package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type schedulerRuntime struct{mu sync.Mutex;states map[string]string;provisions int}
func(r *schedulerRuntime)Provision(_ ProvisionRequest,id string)error{r.mu.Lock();defer r.mu.Unlock();r.provisions++;r.states[id]="running";return nil}
func(r *schedulerRuntime)Inspect(id string)(string,error){r.mu.Lock();defer r.mu.Unlock();state,ok:=r.states[id];if !ok{return "stopped",nil};return state,nil}
func(r *schedulerRuntime)Terminate(id string)error{r.mu.Lock();defer r.mu.Unlock();r.states[id]="stopped";return nil}

func schedulerTestConfig(api string)SchedulerConfig{return SchedulerConfig{
	PlatformAPIBaseURL:api,WorkerID:"forgeos-host-01",Architectures:[]string{"x86_64"},ROMBases:[]string{"lineage"},
	LeaseSeconds:180,PollIntervalSeconds:1,MaxConcurrent:1,
	Resources:Resources{CPUCores:4,MemoryMiB:8192,DiskGiB:200,ProcessLimit:2048,WallTimeSeconds:3600},
	ImageDigests:map[string]string{"x86_64":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	EgressPolicyID:"source-egress",
}}

func TestNewSchedulerRejectsUnpinnedImageAndUnsafeResourceProfile(t *testing.T){
	rt:=&schedulerRuntime{states:map[string]string{}}
	srv,err:=NewServer(Config{BearerToken:"01234567890123456789012345678901",SigningKey:make([]byte,ed25519.PrivateKeySize),StateDir:filepath.Join(t.TempDir(),"state"),Runtime:rt})
	if err!=nil{t.Fatal(err)}
	cfg:=schedulerTestConfig("https://forgeos.example");cfg.ImageDigests=nil
	if _,err:=NewScheduler(srv,cfg,"01234567890123456789012345678901");err==nil{t.Fatal("expected missing image digest rejection")}
	cfg=schedulerTestConfig("https://forgeos.example");cfg.Resources.ProcessLimit=1
	if _,err:=NewScheduler(srv,cfg,"01234567890123456789012345678901");err==nil{t.Fatal("expected unsafe resource profile rejection")}
	cfg=schedulerTestConfig("http://forgeos.example")
	if _,err:=NewScheduler(srv,cfg,"01234567890123456789012345678901");err==nil{t.Fatal("expected non-HTTPS platform rejection")}
}

func TestSchedulerClaimsBuildsAndConfirmsTeardown(t *testing.T){
	snapshot:=json.RawMessage(`{"configuration":{"romBase":"lineage"},"device":{"architecture":"x86_64"}}`)
	canonical,err:=canonicalJSON(snapshot);if err!=nil{t.Fatal(err)}
	digest:=sha256.Sum256(canonical)
	jobID:="123e4567-e89b-42d3-a456-426614174000"
	leaseToken:="123e4567-e89b-42d3-a456-426614174001"
	var mu sync.Mutex;claimed:=false
	platform:=httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
		if r.Header.Get("Authorization")!="Bearer 01234567890123456789012345678901"{http.Error(w,"unauthorized",401);return}
		switch r.URL.Path{
		case "/api/internal/build-jobs/claim":
			mu.Lock();first:=!claimed;claimed=true;mu.Unlock()
			if !first{_,_=w.Write([]byte(`{"job":null}`));return}
			_ = json.NewEncoder(w).Encode(map[string]any{"job":map[string]any{"id":jobID,"snapshot":snapshot,"snapshotSha256":hex.EncodeToString(digest[:]),"attempts":1,"leaseToken":leaseToken,"leaseExpiresAt":time.Now().Add(3*time.Minute)}})
		case "/api/internal/guest-bootstrap/issue":
			_ = json.NewEncoder(w).Encode(map[string]any{"credential":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","jobId":jobID,"attempt":1,"expiresAt":time.Now().Add(3*time.Minute)})
		case "/api/internal/build-jobs/"+jobID+"/status":
			_ = json.NewEncoder(w).Encode(map[string]any{"job":map[string]any{"id":jobID,"status":"succeeded","attempts":1,"workerId":"","leaseExpiresAt":nil}})
		default:http.Error(w,"unexpected route "+r.URL.Path,404)
		}
	}))
	defer platform.Close()
	rt:=&schedulerRuntime{states:map[string]string{}}
	srv,err:=NewServer(Config{BearerToken:"01234567890123456789012345678901",SigningKey:make([]byte,ed25519.PrivateKeySize),StateDir:filepath.Join(t.TempDir(),"state"),Runtime:rt})
	if err!=nil{t.Fatal(err)}
	cfg:=schedulerTestConfig(platform.URL)
	scheduler,err:=NewScheduler(srv,cfg,"01234567890123456789012345678901");if err!=nil{t.Fatal(err)}
	scheduler.client=platform.Client()
	ctx,cancel:=context.WithTimeout(context.Background(),1500*time.Millisecond);defer cancel()
	if err:=scheduler.Run(ctx);err!=nil{t.Fatal(err)}
	rt.mu.Lock();defer rt.mu.Unlock()
	if rt.provisions!=1{t.Fatalf("expected one VM provision, got %d",rt.provisions)}
	if len(rt.states)!=1{t.Fatalf("expected one VM state, got %d",len(rt.states))}
	for id,state:=range rt.states{if state!="stopped"{t.Fatalf("VM %s was not torn down: %s",id,state)}}
	_ = fmt.Sprintf("%s",jobID)
}
