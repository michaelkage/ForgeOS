package agent

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type fakeRuntime struct{mu sync.Mutex;states map[string]string;profiles map[string]IsolationProfile;provisions int}
func(f *fakeRuntime)Provision(req ProvisionRequest,id string)error{f.mu.Lock();defer f.mu.Unlock();f.provisions++;f.states[id]="running";f.profiles[id]=IsolationProfile{FirecrackerMicroVM:true,DedicatedKernel:true,Jailer:true,NonRootVMM:true,NoHostMounts:true,NoContainerSocket:true,NoHostPIDNamespace:true,EncryptedEphemeralDisk:true,HardCPULimit:true,HardMemoryLimit:true,HardDiskLimit:true,HardProcessLimit:true,WallTimeLimit:true,EgressFiltering:true,MetadataBlocked:true,DestroyAfterJob:true,EgressPolicyID:req.EgressPolicyID,Resources:req.Resources};return nil}
func(f *fakeRuntime)Inspect(id string)(string,error){f.mu.Lock();defer f.mu.Unlock();return f.states[id],nil}
func(f *fakeRuntime)Terminate(id string)error{f.mu.Lock();defer f.mu.Unlock();f.states[id]="stopped";return nil}
func(f *fakeRuntime)Evidence(id string)(IsolationProfile,error){f.mu.Lock();defer f.mu.Unlock();return f.profiles[id],nil}

func TestHostAgentSignsProvisionStateAndTermination(t *testing.T){
	pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
	rt:=&fakeRuntime{states:map[string]string{},profiles:map[string]IsolationProfile{}}
	s,err:=NewServer(Config{BearerToken:"01234567890123456789012345678901",SigningKey:priv,StateDir:filepath.Join(t.TempDir(),"state"),Runtime:rt});if err!=nil{t.Fatal(err)}
	server:=httptest.NewServer(s.Handler());defer server.Close()
	reqBody:=ProvisionRequest{RequestID:"123e4567-e89b-42d3-a456-426614174001",JobID:"123e4567-e89b-42d3-a456-426614174000",Attempt:1,Architecture:"x86_64",ROMBase:"lineage",ImageDigest:"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",Resources:Resources{CPUCores:4,MemoryMiB:8192,DiskGiB:200,ProcessLimit:2048,WallTimeSeconds:3600},EgressPolicyID:"test-egress",BootstrapCredential:"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
	body,_:=json.Marshal(reqBody)
	req,_:=http.NewRequest(http.MethodPost,server.URL+"/v1/workers",bytes.NewReader(body));req.Header.Set("Authorization","Bearer 01234567890123456789012345678901");req.Header.Set("Content-Type","application/json")
	resp,err:=http.DefaultClient.Do(req);if err!=nil{t.Fatal(err)};defer resp.Body.Close()
	if resp.StatusCode!=201{t.Fatalf("expected 201, got %d",resp.StatusCode)}
	var provision ProvisionResponse;if err:=json.NewDecoder(resp.Body).Decode(&provision);err!=nil{t.Fatal(err)}
	payloadBytes,err:=canonicalJSON(provision.Attestation.Payload);if err!=nil{t.Fatal(err)}
	sig,err:=base64Decode(provision.Attestation.Signature);if err!=nil{t.Fatal(err)}
	if !ed25519.Verify(pub,payloadBytes,sig){t.Fatal("provisioning attestation signature invalid")}
	if provision.Attestation.Payload.IsolationProfile.EgressPolicyID!="test-egress"{t.Fatal("egress policy missing from signed evidence")}
	stateReq,_:=http.NewRequest(http.MethodGet,server.URL+"/v1/workers/"+provision.Instance.InstanceID,nil);stateReq.Header.Set("Authorization","Bearer 01234567890123456789012345678901")
	stateResp,err:=http.DefaultClient.Do(stateReq);if err!=nil{t.Fatal(err)};defer stateResp.Body.Close()
	var state StateResponse;if err:=json.NewDecoder(stateResp.Body).Decode(&state);err!=nil{t.Fatal(err)}
	if state.State!="running"{t.Fatalf("expected running, got %s",state.State)}
	statePayload:=StatePayload{Provider:state.Provider,InstanceID:state.InstanceID,State:state.State,ObservedAt:state.ObservedAt}
	b,_:=canonicalJSON(statePayload);ss,_:=base64Decode(state.Signature);if !ed25519.Verify(pub,b,ss){t.Fatal("state signature invalid")}
	termBody:=[]byte(`{"requestId":"123e4567-e89b-42d3-a456-426614174002","reason":"test teardown"}`)
	termReq,_:=http.NewRequest(http.MethodPost,server.URL+"/v1/workers/"+provision.Instance.InstanceID+"/terminate",bytes.NewReader(termBody));termReq.Header.Set("Authorization","Bearer 01234567890123456789012345678901")
	termResp,err:=http.DefaultClient.Do(termReq);if err!=nil{t.Fatal(err)};defer termResp.Body.Close()
	if termResp.StatusCode!=200{t.Fatalf("expected 200 termination, got %d",termResp.StatusCode)}
	if rt.provisions!=1{t.Fatalf("expected one provision, got %d",rt.provisions)}
}

func TestHostAgentRejectsMissingServiceCredential(t *testing.T){
	_,priv,_:=ed25519.GenerateKey(rand.Reader)
	s,err:=NewServer(Config{BearerToken:"01234567890123456789012345678901",SigningKey:priv,StateDir:filepath.Join(t.TempDir(),"state"),Runtime:&fakeRuntime{states:map[string]string{},profiles:map[string]IsolationProfile{}}});if err!=nil{t.Fatal(err)}
	req:=httptest.NewRequest(http.MethodGet,"/v1/workers/fc-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",nil);rec:=httptest.NewRecorder();s.Handler().ServeHTTP(rec,req)
	if rec.Code!=401{t.Fatalf("expected 401, got %d",rec.Code)}
}

func base64Decode(s string)([]byte,error){return base64.StdEncoding.DecodeString(s)}
var _=time.Second
