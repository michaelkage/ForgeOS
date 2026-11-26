//go:build linux

package guest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var uuidRE=regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var credentialRE=regexp.MustCompile(`^[A-Za-z0-9_-]{40,64}$`)
var digestRE=regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

type BootstrapPayload struct {
	SchemaVersion int `json:"schemaVersion"`
	JobID string `json:"jobId"`
	WorkerID string `json:"workerId"`
	Attempt int `json:"attempt"`
	Architecture string `json:"architecture"`
	ImageDigest string `json:"imageDigest"`
	APIBaseURL string `json:"apiBaseUrl"`
	BootstrapCredential string `json:"bootstrapCredential"`
	Nonce string `json:"nonce"`
	IssuedAt time.Time `json:"issuedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
	Resources struct { CPUCores int `json:"cpuCores"`; MemoryMiB int `json:"memoryMiB"`; DiskGiB int `json:"diskGiB"`; ProcessLimit int `json:"processLimit"`; WallTimeSeconds int `json:"wallTimeSeconds"` } `json:"resources"`
}
type Envelope struct { Payload BootstrapPayload `json:"payload"`; Signature string `json:"signature"` }
type VerifiedBootstrap struct { Payload BootstrapPayload; API *url.URL }
type RedeemedJob struct { JobID string `json:"jobId"`; Attempt int `json:"attempt"`; WorkerID string `json:"workerId"`; LeaseToken string `json:"leaseToken"`; Snapshot json.RawMessage `json:"snapshot"`; SnapshotSHA256 string `json:"snapshotSha256"` }

func VerifyEnvelope(raw []byte,publicKey ed25519.PublicKey,now time.Time)(VerifiedBootstrap,error){
	if len(raw)==0||len(raw)>64*1024{return VerifiedBootstrap{},errors.New("bootstrap envelope size is invalid")}
	var env Envelope
	dec:=json.NewDecoder(bytes.NewReader(raw));dec.DisallowUnknownFields()
	if err:=dec.Decode(&env);err!=nil{return VerifiedBootstrap{},errors.New("bootstrap envelope is malformed")}
	if len(publicKey)!=ed25519.PublicKeySize{return VerifiedBootstrap{},errors.New("pinned host-agent public key is invalid")}
	sig,err:=base64.StdEncoding.DecodeString(env.Signature);if err!=nil||len(sig)!=ed25519.SignatureSize{return VerifiedBootstrap{},errors.New("bootstrap signature encoding is invalid")}
	canonical,err:=canonicalJSON(env.Payload);if err!=nil||!ed25519.Verify(publicKey,canonical,sig){return VerifiedBootstrap{},errors.New("bootstrap signature verification failed")}
	p:=env.Payload
	if p.SchemaVersion!=1{return VerifiedBootstrap{},errors.New("unsupported bootstrap schema")}
	if !workerIDValid(p.WorkerID){return VerifiedBootstrap{},errors.New("bootstrap worker identity is invalid")}
	if !uuidRE.MatchString(p.JobID)||p.Attempt<1||p.Attempt>20||(p.Architecture!="x86_64"&&p.Architecture!="arm64")||!digestRE.MatchString(p.ImageDigest)||!credentialRE.MatchString(p.BootstrapCredential)||!uuidRE.MatchString(p.Nonce){return VerifiedBootstrap{},errors.New("bootstrap identity or credential is invalid")}
	if p.Resources.CPUCores<2||p.Resources.CPUCores>128||p.Resources.MemoryMiB<4096||p.Resources.MemoryMiB>1048576||p.Resources.DiskGiB<100||p.Resources.DiskGiB>4096||p.Resources.ProcessLimit<128||p.Resources.ProcessLimit>65536||p.Resources.WallTimeSeconds<60||p.Resources.WallTimeSeconds>172800{return VerifiedBootstrap{},errors.New("bootstrap resource limits are invalid")}
	if p.IssuedAt.IsZero()||p.ExpiresAt.IsZero()||p.IssuedAt.After(now.Add(30*time.Second))||now.Sub(p.IssuedAt)>time.Minute||!p.ExpiresAt.After(now)||p.ExpiresAt.After(now.Add(5*time.Minute))||!p.ExpiresAt.After(p.IssuedAt){return VerifiedBootstrap{},errors.New("bootstrap envelope is expired or outside its validity window")}
	api,err:=url.Parse(p.APIBaseURL);if err!=nil||api.Scheme!="https"||api.Host==""||api.User!=nil||api.RawQuery!=""||api.Fragment!=""{return VerifiedBootstrap{},errors.New("bootstrap API endpoint must be credential-free HTTPS")}
	return VerifiedBootstrap{Payload:p,API:api},nil
}

func canonicalJSON(v any)([]byte,error){
	raw,err:=json.Marshal(v);if err!=nil{return nil,err}
	var decoded any;d:=json.NewDecoder(bytes.NewReader(raw));d.UseNumber();if err=d.Decode(&decoded);err!=nil{return nil,err}
	return canonicalValue(decoded)
}
func canonicalValue(v any)([]byte,error){
	switch x:=v.(type){
	case map[string]any:
		keys:=make([]string,0,len(x));for k:=range x{keys=append(keys,k)}
		sortStrings(keys);var b bytes.Buffer;b.WriteByte('{')
		for i,k:=range keys{if i>0{b.WriteByte(',')};kb,_:=json.Marshal(k);vb,e:=canonicalValue(x[k]);if e!=nil{return nil,e};b.Write(kb);b.WriteByte(':');b.Write(vb)}
		b.WriteByte('}');return b.Bytes(),nil
	case []any:
		var b bytes.Buffer;b.WriteByte('[');for i,a:=range x{if i>0{b.WriteByte(',')};z,e:=canonicalValue(a);if e!=nil{return nil,e};b.Write(z)};b.WriteByte(']');return b.Bytes(),nil
	default:return json.Marshal(v)
	}
}
func sortStrings(a []string){for i:=1;i<len(a);i++{for j:=i;j>0&&a[j]<a[j-1];j--{a[j],a[j-1]=a[j-1],a[j]}}}

type Config struct {
	PublicKeyPath string
	WorkerID string
	WorkerPath string
	ArtifactPath string
	VsockPort uint32
}
func Run(ctx context.Context,cfg Config)error{
	if !filepath.IsAbs(cfg.WorkerPath)||!filepath.IsAbs(cfg.ArtifactPath){return errors.New("guest worker and artifact paths must be absolute")}
	if err:=trustedExecutable(cfg.WorkerPath);err!=nil{return err}
	pub,err:=readEd25519PublicKey(cfg.PublicKeyPath);if err!=nil{return err}
	if cfg.VsockPort==0{cfg.VsockPort=4050}
	listener,err:=listenVsock(cfg.VsockPort);if err!=nil{return fmt.Errorf("listen for host bootstrap over vsock: %w",err)}
	defer listener.Close()
	_ = listener.(*vsockListener).SetDeadline(time.Now().Add(2*time.Minute))
	conn,err:=listener.Accept();if err!=nil{return fmt.Errorf("accept host bootstrap: %w",err)}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10*time.Second))
	var header [4]byte;if _,err:=io.ReadFull(conn,header[:]);err!=nil{return errors.New("read bootstrap frame length failed")}
	n:=uint32(header[0])<<24|uint32(header[1])<<16|uint32(header[2])<<8|uint32(header[3])
	if n==0||n>64*1024{return errors.New("bootstrap frame length is invalid")}
	raw:=make([]byte,n);if _,err:=io.ReadFull(conn,raw);err!=nil{return errors.New("read bootstrap frame failed")}
	verified,err:=VerifyEnvelope(raw,pub,time.Now());if err!=nil{return err}
	job,err:=redeem(ctx,verified);if err!=nil{return err}
	if job.JobID!=verified.Payload.JobID||job.Attempt!=verified.Payload.Attempt||job.WorkerID!=verified.Payload.WorkerID||!workerIDValid(job.WorkerID)||!uuidRE.MatchString(job.LeaseToken){return errors.New("redeemed job does not match signed bootstrap identity")}
	snapshot,err:=canonicalRaw(job.Snapshot);if err!=nil{return err}
	sum:=sha256.Sum256(snapshot)
	if "sha256:"+hex.EncodeToString(sum[:])!=job.SnapshotSHA256{return errors.New("immutable build snapshot digest mismatch")}
	workerCgroup,err:=setupGuestProcessCgroup(verified.Payload.Resources.ProcessLimit);if err!=nil{return err}
	if err:=os.MkdirAll("/workspace",0700);err!=nil{return err}
	mount:=exec.Command("mount","-t","ext4","-o","nodev,nosuid","/dev/vdb","/workspace");mount.Stdout=io.Discard;mount.Stderr=io.Discard
	if err:=mount.Run();err!=nil{return errors.New("encrypted guest workspace disk could not be mounted")};if err:=os.Chown("/workspace",10000,10000);err!=nil{return err}
	workspace:="/workspace/forgeos"
	if err:=os.MkdirAll(workspace,0700);err!=nil{return err};if err:=os.Chown(workspace,10000,10000);err!=nil{return err}
	artifactRel,relErr:=filepath.Rel(workspace,cfg.ArtifactPath);if relErr!=nil||artifactRel==".."||strings.HasPrefix(artifactRel,".."+string(os.PathSeparator)){return errors.New("artifact output must be stored inside the encrypted job workspace")}
	snapshotPath:=filepath.Join(workspace,"snapshot.json")
	if err:=os.WriteFile(snapshotPath,snapshot,0400);err!=nil{return err};if err:=os.Chown(snapshotPath,10000,10000);err!=nil{return err}
	if _,err:=conn.Write([]byte("BOOTSTRAP_REDEEMED\n"));err!=nil{return errors.New("unable to acknowledge prepared guest bootstrap")}
	_ = conn.Close()
	runCtx,cancel:=context.WithCancel(ctx);defer cancel()
	heartbeatDone:=make(chan error,1)
	go heartbeatLoop(runCtx,verified.API,job,cancel,heartbeatDone)
	self,err:=os.Executable();if err!=nil{return err}
	cmdArgs:=[]string{"--worker-child",workerCgroup,cfg.WorkerPath,"--snapshot",snapshotPath,"--artifact",cfg.ArtifactPath}
	cmd:=exec.CommandContext(runCtx,self,cmdArgs...)
	cmd.Dir=workspace
	cmd.Env=[]string{"PATH=/usr/local/bin:/usr/bin:/bin","HOME="+workspace,"TMPDIR=/tmp","FORGEOS_JOB_ID="+job.JobID,"FORGEOS_JOB_ATTEMPT="+strconv.Itoa(job.Attempt)}
	if err:=cmd.Run();err!=nil{
		cancel();_ = killGuestWorkerCgroup(workerCgroup)
		_ = reportFailure(context.Background(),verified.API,job,"worker_execution_failed","The isolated build worker exited unsuccessfully.")
		return powerOffGuest()
	}
	if err:=killGuestWorkerCgroup(workerCgroup);err!=nil{_ = reportFailure(context.Background(),verified.API,job,"worker_process_cleanup_failed","Guest build worker processes could not be stopped.");return powerOffGuest()}
	select{case err:=<-heartbeatDone:if err!=nil{_ = reportFailure(context.Background(),verified.API,job,"worker_lease_lost","The build worker lease heartbeat was lost.");return powerOffGuest()};default:}
	cancel()
	if err:=uploadArtifact(ctx,verified.API,job,cfg.ArtifactPath);err!=nil{
		_ = reportFailure(context.Background(),verified.API,job,"artifact_upload_failed","The build artifact could not be uploaded and verified.")
		return powerOffGuest()
	}
	return powerOffGuest()
}

func setupGuestProcessCgroup(limit int)(string,error){
	const root="/sys/fs/cgroup"
	if !isCgroup2Mounted(){if err:=os.MkdirAll(root,0755);err!=nil{return "",err};cmd:=exec.Command("mount","-t","cgroup2","none",root);cmd.Env=[]string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin","LANG=C","LC_ALL=C"};cmd.Stdout=io.Discard;cmd.Stderr=io.Discard;if err:=cmd.Run();err!=nil{return "",errors.New("guest cgroup v2 mount failed")}}
	controllers,err:=os.ReadFile(filepath.Join(root,"cgroup.controllers"));if err!=nil||!strings.Contains(" "+string(controllers)+" "," pids "){return "",errors.New("guest kernel does not expose the cgroup v2 pids controller")}
	selfCgroup,err:=currentCgroupPath();if err!=nil{return "",err}
	subtreePath:=filepath.Join(selfCgroup,"cgroup.subtree_control")
	subtree,err:=os.ReadFile(subtreePath);if err!=nil{return "",err}
	if !strings.Contains(" "+string(subtree)+" "," pids "){
		control:=filepath.Join(selfCgroup,"forgeos-control")
		if err:=os.MkdirAll(control,0755);err!=nil{return "",err}
		if err:=os.WriteFile(filepath.Join(control,"cgroup.procs"),[]byte(strconv.Itoa(os.Getpid())),0644);err!=nil{return "",errors.New("unable to move guest agent into its delegated control cgroup")}
		if err:=os.WriteFile(subtreePath,[]byte("+pids"),0644);err!=nil{return "",errors.New("guest systemd unit must delegate the pids controller")}
	}
	worker:=filepath.Join(selfCgroup,"forgeos-worker")
	if err:=os.MkdirAll(worker,0755);err!=nil{return "",err}
	if err:=os.WriteFile(filepath.Join(worker,"pids.max"),[]byte(strconv.Itoa(limit)),0644);err!=nil{return "",errors.New("unable to enforce guest process limit")};actualLimit,err:=os.ReadFile(filepath.Join(worker,"pids.max"));if err!=nil||strings.TrimSpace(string(actualLimit))!=strconv.Itoa(limit){return "",errors.New("guest process limit could not be independently verified")}
	procs,err:=os.ReadFile(filepath.Join(worker,"cgroup.procs"));if err!=nil{return "",err};if len(bytes.TrimSpace(procs))!=0{return "",errors.New("guest worker cgroup is not empty at job start")}
	return worker,nil
}
func currentCgroupPath()(string,error){
	b,err:=os.ReadFile("/proc/self/cgroup");if err!=nil{return "",err}
	for _,line:=range strings.Split(string(b),"\n"){if strings.HasPrefix(line,"0::"){rel:=strings.TrimPrefix(strings.TrimSpace(strings.TrimPrefix(line,"0::")),"/");if rel==""||strings.Contains(rel,".."){return "",errors.New("guest agent is not running in a delegated service cgroup")};path:=filepath.Join("/sys/fs/cgroup",rel);if !strings.HasPrefix(path,"/sys/fs/cgroup/"){return "",errors.New("invalid guest service cgroup path")};return path,nil}}
	return "",errors.New("unified cgroup v2 membership is unavailable")
}

func isCgroup2Mounted()bool{
	b,err:=os.ReadFile("/proc/self/mountinfo");if err!=nil{return false}
	for _,line:=range strings.Split(string(b),"\n"){if strings.Contains(line," - cgroup2 ")&&strings.Contains(line," /sys/fs/cgroup "){return true}}
	return false
}
func killGuestWorkerCgroup(path string)error{
	if !filepath.IsAbs(path)||!strings.HasPrefix(filepath.Clean(path),"/sys/fs/cgroup/")||filepath.Base(filepath.Clean(path))!="forgeos-worker"{return errors.New("invalid guest worker cgroup path")}
	path=filepath.Clean(path)
	procs:=filepath.Join(path,"cgroup.procs")
	if _,err:=os.Stat(procs);err!=nil{return err}
	if _,err:=os.Stat(filepath.Join(path,"cgroup.kill"));err==nil{
		if err:=os.WriteFile(filepath.Join(path,"cgroup.kill"),[]byte("1"),0200);err!=nil{return err}
	}else{
		b,err:=os.ReadFile(procs);if err!=nil{return err}
		for _,raw:=range strings.Fields(string(b)){pid,_:=strconv.Atoi(raw);if pid>1{_ = syscall.Kill(pid,syscall.SIGKILL)}}
	}
	deadline:=time.Now().Add(5*time.Second)
	for time.Now().Before(deadline){b,err:=os.ReadFile(procs);if err!=nil{return err};if len(bytes.TrimSpace(b))==0{return nil};time.Sleep(50*time.Millisecond)}
	return errors.New("guest worker cgroup still contains processes after teardown")
}

func ExecWorkerChild(cgroupPath,workerPath string,args []string)error{
	cleanCgroup:=filepath.Clean(cgroupPath);if os.Geteuid()!=0||!filepath.IsAbs(cgroupPath)||!strings.HasPrefix(cleanCgroup,"/sys/fs/cgroup/")||filepath.Base(cleanCgroup)!="forgeos-worker"||strings.Contains(cleanCgroup,".."){return errors.New("worker child must enter the preconfigured guest cgroup as root")}
	if err:=trustedExecutable(workerPath);err!=nil{return err}
	if err:=os.WriteFile(filepath.Join(cgroupPath,"cgroup.procs"),[]byte(strconv.Itoa(os.Getpid())),0644);err!=nil{return err}
	if err:=syscall.Setgroups([]int{});err!=nil{return err}
	if err:=syscall.Setgid(10000);err!=nil{return err}
	if err:=syscall.Setuid(10000);err!=nil{return err}
	_,_,errno:=syscall.Syscall6(syscall.SYS_PRCTL,38,1,0,0,0,0);if errno!=0{return errno}
	argv:=append([]string{workerPath},args...)
	return syscall.Exec(workerPath,argv,os.Environ())
}
func powerOffGuest()error{
	if err:=syscall.Reboot(0x4321fedc);err!=nil{return fmt.Errorf("guest poweroff failed: %w",err)}
	return nil
}

func redeem(ctx context.Context,b VerifiedBootstrap)(RedeemedJob,error){
	var out RedeemedJob
	req,err:=http.NewRequestWithContext(ctx,http.MethodPost,b.API.ResolveReference(&url.URL{Path:"/api/internal/guest-bootstrap/redeem"}).String(),nil);if err!=nil{return out,err}
	req.Header.Set("Authorization","Bearer "+b.Payload.BootstrapCredential)
	resp,err:=newHTTPClient().Do(req);if err!=nil{return out,err};defer resp.Body.Close()
	if resp.StatusCode!=http.StatusOK{return out,fmt.Errorf("guest bootstrap redemption rejected: HTTP %d",resp.StatusCode)}
	if err:=json.NewDecoder(io.LimitReader(resp.Body,2*1024*1024)).Decode(&out);err!=nil{return out,err}
	return out,nil
}

func heartbeatLoop(ctx context.Context,api *url.URL,job RedeemedJob,cancel context.CancelFunc,done chan<- error){
	t:=time.NewTicker(60*time.Second);defer t.Stop()
	for{select{case<-ctx.Done():done<-nil;return;case<-t.C:
		body:=map[string]any{"workerId":job.WorkerID,"leaseToken":job.LeaseToken,"leaseSeconds":180}
		if _,err:=postJSON(ctx,api,"/api/internal/build-jobs/"+job.JobID+"/heartbeat",job.LeaseToken,body,nil);err!=nil{cancel();done<-err;return}
	}}
}
func uploadArtifact(ctx context.Context,api *url.URL,job RedeemedJob,path string)error{
	fd,err:=syscall.Open(path,syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW,0);if err!=nil{return err};f:=os.NewFile(uintptr(fd),path);defer f.Close()
	st,err:=f.Stat();if err!=nil{return err};sys,ok:=st.Sys().(*syscall.Stat_t);if !st.Mode().IsRegular()||st.Size()<=0||st.Size()>20*1024*1024*1024||!ok||sys.Uid!=10000||st.Mode().Perm()&0022!=0{return errors.New("build artifact must be a bounded, non-writable regular file owned by the unprivileged worker")}
	h:=sha256.New();if _,err:=io.Copy(h,f);err!=nil{return err};digest:=hex.EncodeToString(h.Sum(nil));if _,err:=f.Seek(0,io.SeekStart);err!=nil{return err}
	var intent struct{URL string `json:"url"`;RequiredHeaders map[string]string `json:"requiredHeaders"`}
	_,err=postJSON(ctx,api,"/api/internal/build-jobs/"+job.JobID+"/artifact-upload",job.LeaseToken,map[string]any{"workerId":job.WorkerID,"leaseToken":job.LeaseToken,"sha256":digest,"sizeBytes":st.Size()},&intent);if err!=nil{return err}
	target,err:=url.Parse(intent.URL);if err!=nil||target.Scheme!="https"||target.Host==""||target.User!=nil{return errors.New("artifact upload URL must use HTTPS")}
	req,err:=http.NewRequestWithContext(ctx,http.MethodPut,target.String(),f);if err!=nil{return err}
	req.ContentLength=st.Size();req.Header.Set("Content-Type","application/zip");req.Header.Set("If-None-Match","*")
	for k,v:=range intent.RequiredHeaders{if strings.EqualFold(k,"content-type")||strings.EqualFold(k,"content-length")||strings.EqualFold(k,"if-none-match"){continue};req.Header.Set(k,v)}
	resp,err:=newHTTPClient().Do(req);if err!=nil{return err};resp.Body.Close();if resp.StatusCode<200||resp.StatusCode>=300{return fmt.Errorf("artifact object upload failed: HTTP %d",resp.StatusCode)}
	_,err=postJSON(ctx,api,"/api/internal/build-jobs/"+job.JobID+"/complete",job.LeaseToken,map[string]any{"workerId":job.WorkerID,"leaseToken":job.LeaseToken,"artifact":map[string]any{"sha256":digest,"sizeBytes":st.Size(),"contentType":"application/zip"}},nil)
	return err
}
func reportFailure(ctx context.Context,api *url.URL,job RedeemedJob,code,message string)error{
	_,err:=postJSON(ctx,api,"/api/internal/build-jobs/"+job.JobID+"/fail",job.LeaseToken,map[string]any{"workerId":job.WorkerID,"leaseToken":job.LeaseToken,"errorCode":code,"retryable":true,"message":message},nil)
	return err
}
func postJSON(ctx context.Context,api *url.URL,path,token string,body any,out any)(int,error){
	raw,err:=json.Marshal(body);if err!=nil{return 0,err}
	target:=api.ResolveReference(&url.URL{Path:path})
	req,err:=http.NewRequestWithContext(ctx,http.MethodPost,target.String(),bytes.NewReader(raw));if err!=nil{return 0,err}
	req.Header.Set("Authorization","Bearer "+token);req.Header.Set("Content-Type","application/json")
	resp,err:=newHTTPClient().Do(req);if err!=nil{return 0,err};defer resp.Body.Close()
	if resp.StatusCode<200||resp.StatusCode>=300{return resp.StatusCode,fmt.Errorf("platform request rejected: HTTP %d",resp.StatusCode)}
	if out!=nil{if err:=json.NewDecoder(io.LimitReader(resp.Body,2*1024*1024)).Decode(out);err!=nil{return resp.StatusCode,err}}
	return resp.StatusCode,nil
}
func canonicalRaw(raw json.RawMessage)([]byte,error){var v any;d:=json.NewDecoder(bytes.NewReader(raw));d.UseNumber();if err:=d.Decode(&v);err!=nil{return nil,err};return canonicalValue(v)}
func newHTTPClient()*http.Client{return &http.Client{Timeout:30*time.Second,CheckRedirect:func(*http.Request,[]*http.Request)error{return errors.New("redirects are not allowed")}}}
func workerIDValid(s string)bool{return len(s)>=3&&len(s)<=64&&regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`).MatchString(s)}
func trustedExecutable(path string)error{st,err:=os.Lstat(path);if err!=nil{return err};sys,ok:=st.Sys().(*syscall.Stat_t);if !st.Mode().IsRegular()||st.Mode()&os.ModeSymlink!=0||st.Mode().Perm()&0022!=0||!ok||sys.Uid!=0{return errors.New("build worker executable must be a root-owned, non-writable regular file")};return nil}
func readEd25519PublicKey(path string)(ed25519.PublicKey,error){
	b,err:=os.ReadFile(path);if err!=nil{return nil,err}
	st,statErr:=os.Lstat(path);if statErr!=nil{return nil,statErr};sys,ok:=st.Sys().(*syscall.Stat_t);if !ok||sys.Uid!=0||st.Mode()&0022!=0||st.Mode()&os.ModeSymlink!=0{return nil,errors.New("host public key must be root-owned and not writable by group or others")};block,_:=pem.Decode(b);if block==nil{return nil,errors.New("host public key PEM is invalid")}
	key,err:=x509.ParsePKIXPublicKey(block.Bytes);if err!=nil{return nil,err}
	pub,ok:=key.(ed25519.PublicKey);if !ok{return nil,errors.New("pinned host public key must be Ed25519")}
	return pub,nil
}
