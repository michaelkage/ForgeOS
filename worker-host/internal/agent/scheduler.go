package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type SchedulerConfig struct {
	PlatformAPIBaseURL string `json:"platformApiBaseUrl"`
	WorkerID string `json:"workerId"`
	Architectures []string `json:"architectures"`
	ROMBases []string `json:"romBases"`
	LeaseSeconds int `json:"leaseSeconds"`
	PollIntervalSeconds int `json:"pollIntervalSeconds"`
	MaxConcurrent int `json:"maxConcurrent"`
	Resources Resources `json:"resources"`
	ImageDigests map[string]string `json:"imageDigests"`
	EgressPolicyID string `json:"egressPolicyId"`
}

type Scheduler struct {
	server *Server
	cfg SchedulerConfig
	api *url.URL
	token string
	client *http.Client
}

type claimedJob struct {
	ID string `json:"id"`
	Snapshot json.RawMessage `json:"snapshot"`
	SnapshotSHA256 string `json:"snapshotSha256"`
	Attempts int `json:"attempts"`
	LeaseToken string `json:"leaseToken"`
	LeaseExpiresAt time.Time `json:"leaseExpiresAt"`
}

type claimedJobResponse struct { Job *claimedJob `json:"job"` }
type issuedCredential struct { Credential string `json:"credential"`; JobID string `json:"jobId"`; Attempt int `json:"attempt"`; ExpiresAt time.Time `json:"expiresAt"` }
type schedulerJobStatus struct { ID string `json:"id"`; Status string `json:"status"`; Attempts int `json:"attempts"`; WorkerID string `json:"workerId"`; LeaseExpiresAt *time.Time `json:"leaseExpiresAt"` }
type schedulerStatusResponse struct { Job schedulerJobStatus `json:"job"` }

func NewScheduler(server *Server,cfg SchedulerConfig,workerToken string)(*Scheduler,error){
	if server==nil||len(workerToken)<32{return nil,errors.New("scheduler server and platform worker token are required")}
	api,err:=url.Parse(cfg.PlatformAPIBaseURL)
	if err!=nil||api.Scheme!="https"||api.Host==""||api.User!=nil||api.RawQuery!=""||api.Fragment!=""{return nil,errors.New("scheduler platform URL must be credential-free HTTPS")}
	if !workerPattern.MatchString(cfg.WorkerID)||!workerPattern.MatchString(cfg.EgressPolicyID){return nil,errors.New("scheduler worker and egress policy IDs are invalid")}
	if len(cfg.Architectures)==0||len(cfg.Architectures)>2||len(cfg.ROMBases)==0||len(cfg.ROMBases)>2{return nil,errors.New("scheduler capabilities are invalid")}
	for _,a:=range cfg.Architectures{if a!="x86_64"&&a!="arm64"{return nil,fmt.Errorf("unsupported scheduler architecture %s",a)};if !digestPattern.MatchString(cfg.ImageDigests[a]){return nil,fmt.Errorf("missing pinned worker image digest for %s",a)}}
	for _,b:=range cfg.ROMBases{if b!="lineage"&&b!="crdroid"{return nil,fmt.Errorf("unsupported scheduler ROM base %s",b)}}
	if cfg.LeaseSeconds==0{cfg.LeaseSeconds=180};if cfg.LeaseSeconds<30||cfg.LeaseSeconds>900{return nil,errors.New("scheduler lease must be between 30 and 900 seconds")}
	if cfg.PollIntervalSeconds==0{cfg.PollIntervalSeconds=5};if cfg.PollIntervalSeconds<1||cfg.PollIntervalSeconds>60{return nil,errors.New("scheduler poll interval must be between 1 and 60 seconds")}
	if cfg.MaxConcurrent==0{cfg.MaxConcurrent=1};if cfg.MaxConcurrent<1||cfg.MaxConcurrent>32{return nil,errors.New("scheduler concurrency must be between 1 and 32")}
	if err:=validateResources(cfg.Resources);err!=nil{return nil,err}
	if lr,ok:=server.cfg.Runtime.(*LinuxRuntime);ok{
		if lr.cfg.WorkerID!=cfg.WorkerID{return nil,errors.New("scheduler worker ID must match the host runtime worker ID")}
		if strings.TrimRight(lr.cfg.BootstrapAPIBaseURL,"/")!=strings.TrimRight(cfg.PlatformAPIBaseURL,"/"){return nil,errors.New("scheduler and guest bootstrap API origins must match")}
		if _,ok:=lr.cfg.EgressPolicies[cfg.EgressPolicyID];!ok{return nil,errors.New("scheduler egress policy is not installed on the host")}
		for _,arch:=range cfg.Architectures{digest:=cfg.ImageDigests[arch];if _,ok:=lr.cfg.ImagePaths[digest];!ok{return nil,fmt.Errorf("worker image %s is not installed on the host",digest)};if _,ok:=lr.cfg.KernelPaths[arch];!ok{return nil,fmt.Errorf("kernel for %s is not installed on the host",arch)}}
	}
	return &Scheduler{server:server,cfg:cfg,api:api,token:workerToken,client:&http.Client{Timeout:20*time.Second,CheckRedirect:func(*http.Request,[]*http.Request)error{return errors.New("scheduler HTTP redirects are forbidden")}}},nil
}

func validateResources(r Resources)error{
	checks:=[][3]int{{r.CPUCores,2,128},{r.MemoryMiB,4096,1048576},{r.DiskGiB,100,4096},{r.ProcessLimit,128,65536},{r.WallTimeSeconds,60,172800}}
	for _,c:=range checks{if c[0]<c[1]||c[0]>c[2]{return errors.New("scheduler resource profile is outside enforced limits")}}
	return nil
}

func (s *Scheduler) Run(ctx context.Context)error{
	active:=make(chan struct{},s.cfg.MaxConcurrent)
	var wg sync.WaitGroup
	ticker:=time.NewTicker(time.Duration(s.cfg.PollIntervalSeconds)*time.Second);defer ticker.Stop()
	for{
		if len(active)<cap(active){
			job,err:=s.claim(ctx)
			if err!=nil&&ctx.Err()==nil{log.Printf("ForgeOS scheduler claim failed: %v",err)}
			if err==nil&&job!=nil{
				active<-struct{}{};wg.Add(1)
				go func(j claimedJob){defer wg.Done();defer func(){<-active}();s.runJob(ctx,j)}(*job)
				continue
			}
		}
		select{case<-ctx.Done():wg.Wait();return nil;case<-ticker.C:}
	}
}

func (s *Scheduler) claim(ctx context.Context)(*claimedJob,error){
	body:=map[string]any{"workerId":s.cfg.WorkerID,"leaseSeconds":s.cfg.LeaseSeconds,"architectures":s.cfg.Architectures,"romBases":s.cfg.ROMBases}
	var response claimedJobResponse
	if err:=s.request(ctx,http.MethodPost,"/api/internal/build-jobs/claim",s.token,body,&response);err!=nil{return nil,err}
	if response.Job==nil{return nil,nil}
	if !uuidPattern.MatchString(response.Job.ID)||!uuidPattern.MatchString(response.Job.LeaseToken)||response.Job.Attempts<1||response.Job.Attempts>20{return nil,errors.New("platform returned an invalid claimed job")}
	return response.Job,nil
}

func (s *Scheduler) runJob(ctx context.Context,job claimedJob){
	fail:=func(code,message string){_ = s.reportFailure(context.Background(),job,code,message)}
	canonical,err:=canonicalJSON(job.Snapshot);if err!=nil{fail("snapshot_invalid","The claimed build snapshot could not be canonicalized.");return}
	sum:=sha256.Sum256(canonical);if hex.EncodeToString(sum[:])!=job.SnapshotSHA256{fail("snapshot_digest_mismatch","The claimed build snapshot digest did not match.");return}
	var snapshot struct{Configuration struct{ROMBase string `json:"romBase"`} `json:"configuration"`;Device struct{Architecture string `json:"architecture"`} `json:"device"`}
	if err:=json.Unmarshal(job.Snapshot,&snapshot);err!=nil{fail("snapshot_invalid","The claimed build snapshot could not be decoded.");return}
	architecture,romBase:=snapshot.Device.Architecture,snapshot.Configuration.ROMBase
	if !contains(s.cfg.Architectures,architecture)||!contains(s.cfg.ROMBases,romBase){fail("worker_capability_mismatch","The claimed job does not match this worker's capabilities.");return}
	credential,err:=s.issueCredential(ctx,job)
	if err!=nil{fail("guest_credential_issue_failed","The one-time guest bootstrap credential could not be issued.");return}
	if credential.JobID!=job.ID||credential.Attempt!=job.Attempts||!bootstrapCredentialPattern.MatchString(credential.Credential)||!credential.ExpiresAt.After(time.Now()){fail("guest_credential_invalid","The platform returned an invalid guest bootstrap credential.");return}
	requestID,err:=randomUUID();if err!=nil{fail("host_request_id_failed","The host could not create a provisioning request ID.");return}
	req:=ProvisionRequest{RequestID:requestID,WorkerID:s.cfg.WorkerID,JobID:job.ID,Attempt:job.Attempts,Architecture:architecture,ROMBase:romBase,ImageDigest:s.cfg.ImageDigests[architecture],Resources:s.cfg.Resources,EgressPolicyID:s.cfg.EgressPolicyID,BootstrapCredential:credential.Credential}
	instance,err:=s.server.ProvisionLocal(req)
	if err!=nil{if instance.InstanceID!=""{s.terminateUntilStopped(instance.InstanceID)};fail("host_provisioning_failed","The isolated Firecracker worker could not be provisioned.");return}
	s.monitorJob(ctx,job,instance)
}

func (s *Scheduler) issueCredential(ctx context.Context,job claimedJob)(issuedCredential,error){
	var out issuedCredential
	body:=map[string]any{"jobId":job.ID,"workerId":s.cfg.WorkerID,"leaseToken":job.LeaseToken}
	err:=s.request(ctx,http.MethodPost,"/api/internal/guest-bootstrap/issue",s.token,body,&out)
	return out,err
}

func (s *Scheduler) monitorJob(ctx context.Context,job claimedJob,instance Instance){
	ticker:=time.NewTicker(5*time.Second);defer ticker.Stop()
	for{
		if ctx.Err()!=nil{s.terminateUntilStopped(instance.InstanceID);return}
		status,err:=s.jobStatus(ctx,job.ID)
		if err!=nil{log.Printf("ForgeOS scheduler status check failed for job %s: %v",job.ID,err)}else{
			if status.Job.Status!="leased"||status.Job.WorkerID!=s.cfg.WorkerID||status.Job.Attempts!=job.Attempts{
				s.terminateUntilStopped(instance.InstanceID);return
			}
			if status.Job.LeaseExpiresAt==nil||time.Now().After(*status.Job.LeaseExpiresAt){
				s.terminateUntilStopped(instance.InstanceID);return
			}
		}
		state,stateErr:=s.server.cfg.Runtime.Inspect(instance.InstanceID)
		if stateErr==nil&&state=="stopped"{
			_ = s.reportFailure(context.Background(),job,"worker_vm_stopped","The isolated worker VM stopped before the platform recorded a terminal job result.")
			s.terminateUntilStopped(instance.InstanceID);return
		}
		if stateErr==nil&&state=="unknown"{
			_ = s.reportFailure(context.Background(),job,"worker_vm_state_unknown","The host could not verify the isolated worker VM state.")
			s.terminateUntilStopped(instance.InstanceID);return
		}
		select{case<-ctx.Done():s.terminateUntilStopped(instance.InstanceID);return;case<-ticker.C:}
	}
}

func (s *Scheduler) terminateUntilStopped(id string){
	for{
		if err:=s.server.TerminateLocal(id);err==nil{return}else{log.Printf("ForgeOS VM teardown pending for %s: %v",id,err)}
		time.Sleep(2*time.Second)
	}
}

func (s *Scheduler) jobStatus(ctx context.Context,id string)(schedulerStatusResponse,error){
	var out schedulerStatusResponse
	err:=s.request(ctx,http.MethodGet,"/api/internal/build-jobs/"+id+"/status",s.token,nil,&out)
	return out,err
}
func (s *Scheduler) reportFailure(ctx context.Context,job claimedJob,code,message string)error{
	body:=map[string]any{"workerId":s.cfg.WorkerID,"leaseToken":job.LeaseToken,"errorCode":code,"retryable":true,"message":message}
	return s.request(ctx,http.MethodPost,"/api/internal/build-jobs/"+job.ID+"/fail",job.LeaseToken,body,nil)
}
func (s *Scheduler) request(ctx context.Context,method,path,token string,body,out any)error{
	var reader io.Reader
	if body!=nil{b,err:=json.Marshal(body);if err!=nil{return err};reader=bytes.NewReader(b)}
	target:=s.api.ResolveReference(&url.URL{Path:path})
	req,err:=http.NewRequestWithContext(ctx,method,target.String(),reader);if err!=nil{return err}
	req.Header.Set("Authorization","Bearer "+token)
	if body!=nil{req.Header.Set("Content-Type","application/json")}
	resp,err:=s.client.Do(req);if err!=nil{return err};defer resp.Body.Close()
	if resp.StatusCode<200||resp.StatusCode>=300{data,_:=io.ReadAll(io.LimitReader(resp.Body,2048));return fmt.Errorf("platform returned HTTP %d: %s",resp.StatusCode,strings.TrimSpace(string(data)))}
	if out!=nil{if err:=json.NewDecoder(io.LimitReader(resp.Body,2*1024*1024)).Decode(out);err!=nil{return err}}
	return nil
}
func contains(values []string,value string)bool{for _,v:=range values{if v==value{return true}};return false}
