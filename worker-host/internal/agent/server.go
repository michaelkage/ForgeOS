package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const providerID = "forgeos-firecracker"
const maxRequestBytes = 64 * 1024

var (
	uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	instancePattern = regexp.MustCompile(`^fc-[a-f0-9]{32}$`)
	workerPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$`)
	digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
)

type Runtime interface {
	Provision(ProvisionRequest, string) error
	Inspect(string) (string, error)
	Terminate(string) error
}

type Config struct {
	BearerToken string
	SigningKey ed25519.PrivateKey
	StateDir string
	Runtime Runtime
}

type storedInstance struct {
	Instance Instance `json:"instance"`
	RequestID string `json:"requestId"`
	Resources Resources `json:"resources"`
	CreatedAt time.Time `json:"createdAt"`
}

type Server struct {
	cfg Config
	mu sync.Mutex
	instances map[string]storedInstance
	requests map[string]string
	mux *http.ServeMux
}

func NewServer(cfg Config) (*Server, error) {
	if len(cfg.BearerToken) < 32 || len(cfg.BearerToken) > 4096 {
		return nil, errors.New("host-agent bearer token must be 32..4096 bytes")
	}
	if len(cfg.SigningKey) != ed25519.PrivateKeySize || cfg.Runtime == nil || cfg.StateDir == "" {
		return nil, errors.New("host-agent signing key, runtime, and state directory are required")
	}
	if err := os.MkdirAll(cfg.StateDir, 0700); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}
	s := &Server{cfg: cfg, instances: map[string]storedInstance{}, requests: map[string]string{}, mux: http.NewServeMux()}
	if err := s.loadState(); err != nil { return nil, err }
	s.mux.HandleFunc("POST /v1/workers", s.handleProvision)
	s.mux.HandleFunc("GET /v1/workers/{id}", s.handleInspect)
	s.mux.HandleFunc("POST /v1/workers/{id}/terminate", s.handleTerminate)
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, map[string]string{"status":"ok"}) })
	return s, nil
}

func (s *Server) Handler() http.Handler {
	return securityHeaders(s.authenticate(s.mux))
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" && r.Method == http.MethodGet { next.ServeHTTP(w,r); return }
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, "Bearer ") { writeError(w,401,"authentication_failed"); return }
		got := []byte(strings.TrimPrefix(header,"Bearer "))
		want := []byte(s.cfg.BearerToken)
		if len(got) != len(want) || subtle.ConstantTimeCompare(got,want) != 1 { writeError(w,401,"authentication_failed"); return }
		next.ServeHTTP(w,r)
	})
}

func (s *Server) handleProvision(w http.ResponseWriter, r *http.Request) {
	body, err := readBounded(r.Body,maxRequestBytes)
	if err != nil { writeError(w,400,"invalid_request_body"); return }
	var req ProvisionRequest
	dec := json.NewDecoder(strings.NewReader(string(body))); dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil { writeError(w,400,"invalid_provision_request"); return }
	if err := validateRequest(req); err != nil { writeError(w,400,"invalid_provision_request"); return }

	s.mu.Lock()
	defer s.mu.Unlock()
	if existingID, ok := s.requests[req.RequestID]; ok {
		existing := s.instances[existingID]
		if existing.Instance.JobID != req.JobID || existing.Instance.Attempt != req.Attempt || existing.Instance.ImageDigest != req.ImageDigest {
			writeError(w,409,"request_id_conflict"); return
		}
		resp, err := s.provisionResponse(existing, req.RequestID)
		if err != nil { writeError(w,500,"attestation_failed"); return }
		writeJSON(w,200,resp); return
	}
	for _, existing := range s.instances {
		if existing.Instance.JobID == req.JobID && existing.Instance.Attempt == req.Attempt {
			writeError(w,409,"job_attempt_already_has_vm"); return
		}
	}
	id := "fc-" + strings.ReplaceAll(randomUUID(),"-","")
	if err := s.cfg.Runtime.Provision(req,id); err != nil {
		_ = s.cfg.Runtime.Terminate(id)
		writeError(w,503,"vm_provisioning_failed"); return
	}
	now := time.Now().UTC()
	instance := Instance{Provider:providerID,InstanceID:id,JobID:req.JobID,Attempt:req.Attempt,Architecture:req.Architecture,ImageDigest:req.ImageDigest,CreatedAt:now}
	record := storedInstance{Instance:instance,RequestID:req.RequestID,Resources:req.Resources,CreatedAt:now}
	s.instances[id]=record; s.requests[req.RequestID]=id
	if err := s.saveState(); err != nil {
		delete(s.instances,id); delete(s.requests,req.RequestID)
		_ = s.cfg.Runtime.Terminate(id)
		writeError(w,500,"state_persistence_failed"); return
	}
	resp, err := s.provisionResponse(record,req.RequestID)
	if err != nil { _ = s.cfg.Runtime.Terminate(id); writeError(w,500,"attestation_failed"); return }
	writeJSON(w,201,resp)
}

func (s *Server) provisionResponse(record storedInstance, nonce string) (ProvisionResponse,error) {
	now:=time.Now().UTC()
	profile:=IsolationProfile{
		FirecrackerMicroVM:true,DedicatedKernel:true,Jailer:true,NonRootVMM:true,NoHostMounts:true,
		NoContainerSocket:true,NoHostPIDNamespace:true,EncryptedEphemeralDisk:true,HardCPULimit:true,
		HardMemoryLimit:true,HardDiskLimit:true,HardProcessLimit:true,WallTimeLimit:true,EgressFiltering:true,
		MetadataBlocked:true,DestroyAfterJob:true,EgressPolicyID:"",Resources:record.Resources,
	}
	// The runtime must attest only after its Linux enforcement path has completed.
	evidence,ok:=s.cfg.Runtime.(interface{ Evidence(string) (IsolationProfile,error) })
	if !ok { return ProvisionResponse{},errors.New("runtime does not provide enforcement evidence") }
	profile,err:=evidence.Evidence(record.Instance.InstanceID); if err!=nil{return ProvisionResponse{},err}
	payload:=AttestationPayload{Provider:providerID,InstanceID:record.Instance.InstanceID,JobID:record.Instance.JobID,Attempt:record.Instance.Attempt,Architecture:record.Instance.Architecture,ImageDigest:record.Instance.ImageDigest,RequestNonce:nonce,IsolationProfile:profile,IssuedAt:now,ExpiresAt:now.Add(90*time.Second)}
	sig,err:=signCanonical(s.cfg.SigningKey,payload); if err!=nil{return ProvisionResponse{},err}
	return ProvisionResponse{Instance:record.Instance,Attestation:SignedAttestation{Payload:payload,Signature:sig}},nil
}

func (s *Server) handleInspect(w http.ResponseWriter,r *http.Request) {
	id:=r.PathValue("id"); if !instancePattern.MatchString(id){writeError(w,400,"invalid_instance_id");return}
	s.mu.Lock(); record,ok:=s.instances[id]; s.mu.Unlock()
	if !ok { writeError(w,404,"worker_not_found");return }
	state,err:=s.cfg.Runtime.Inspect(id); if err!=nil { writeError(w,503,"worker_state_unavailable");return }
	if state!="running" && state!="stopped" && state!="unknown" { writeError(w,503,"invalid_runtime_state");return }
	payload:=StatePayload{Provider:providerID,InstanceID:id,State:state,ObservedAt:time.Now().UTC()}
	sig,err:=signCanonical(s.cfg.SigningKey,payload);if err!=nil{writeError(w,500,"state_signing_failed");return}
	_ = record
	writeJSON(w,200,StateResponse{Provider:payload.Provider,InstanceID:id,State:state,ObservedAt:payload.ObservedAt,Signature:sig})
}

func (s *Server) handleTerminate(w http.ResponseWriter,r *http.Request) {
	id:=r.PathValue("id"); if !instancePattern.MatchString(id){writeError(w,400,"invalid_instance_id");return}
	body,err:=readBounded(r.Body,4096);if err!=nil{writeError(w,400,"invalid_request_body");return}
	var req struct{RequestID string `json:"requestId"`;Reason string `json:"reason"`}
	dec:=json.NewDecoder(strings.NewReader(string(body)));dec.DisallowUnknownFields()
	if dec.Decode(&req)!=nil || !uuidPattern.MatchString(req.RequestID) || strings.TrimSpace(req.Reason)=="" || len(req.Reason)>200 {writeError(w,400,"invalid_termination_request");return}
	s.mu.Lock();_,ok:=s.instances[id];s.mu.Unlock();if !ok{writeError(w,404,"worker_not_found");return}
	if err:=s.cfg.Runtime.Terminate(id);err!=nil{writeError(w,503,"worker_termination_failed");return}
	payload:=TerminatePayload{Provider:providerID,InstanceID:id,Accepted:true,RequestID:req.RequestID}
	sig,err:=signCanonical(s.cfg.SigningKey,payload);if err!=nil{writeError(w,500,"termination_signing_failed");return}
	writeJSON(w,200,TerminateResponse{Provider:payload.Provider,InstanceID:id,Accepted:true,RequestID:req.RequestID,Signature:sig})
}

func (s *Server) loadState() error {
	path:=filepath.Join(s.cfg.StateDir,"instances.json")
	data,err:=os.ReadFile(path);if os.IsNotExist(err){return nil};if err!=nil{return err}
	var records []storedInstance
	if err:=json.Unmarshal(data,&records);err!=nil{return fmt.Errorf("decode host state: %w",err)}
	for _,r:=range records {if !instancePattern.MatchString(r.Instance.InstanceID){return errors.New("invalid instance id in state")};s.instances[r.Instance.InstanceID]=r;s.requests[r.RequestID]=r.Instance.InstanceID}
	return nil
}
func (s *Server) saveState() error {
	records:=make([]storedInstance,0,len(s.instances));for _,r:=range s.instances{records=append(records,r)}
	data,err:=json.Marshal(records);if err!=nil{return err}
	tmp:=filepath.Join(s.cfg.StateDir,"instances.json.tmp")
	if err:=os.WriteFile(tmp,data,0600);err!=nil{return err}
	return os.Rename(tmp,filepath.Join(s.cfg.StateDir,"instances.json"))
}

func validateRequest(r ProvisionRequest) error {
	if !uuidPattern.MatchString(r.RequestID)||!uuidPattern.MatchString(r.JobID)||r.Attempt<1||r.Attempt>20{return errors.New("invalid job identity")}
	if r.Architecture!="x86_64"&&r.Architecture!="arm64"{return errors.New("unsupported architecture")}
	if r.ROMBase!="lineage"&&r.ROMBase!="crdroid"{return errors.New("unsupported ROM base")}
	if !digestPattern.MatchString(r.ImageDigest)||!workerPattern.MatchString(r.EgressPolicyID){return errors.New("invalid image or egress policy")}
	if len(r.BootstrapCredential)<40||len(r.BootstrapCredential)>128{return errors.New("invalid bootstrap credential")}
	bounds:=[][3]int{{r.Resources.CPUCores,2,128},{r.Resources.MemoryMiB,4096,1048576},{r.Resources.DiskGiB,100,4096},{r.Resources.ProcessLimit,128,65536},{r.Resources.WallTimeSeconds,60,172800}}
	for _,b:=range bounds{if b[0]<b[1]||b[0]>b[2]{return errors.New("resource request outside safe bounds")}}
	return nil
}
func readBounded(r io.Reader,n int64)([]byte,error){b,err:=io.ReadAll(io.LimitReader(r,n+1));if err!=nil{return nil,err};if int64(len(b))>n{return nil,errors.New("request too large")};return b,nil}
func writeJSON(w http.ResponseWriter,status int,v any){w.Header().Set("Content-Type","application/json");w.WriteHeader(status);_ = json.NewEncoder(w).Encode(v)}
func writeError(w http.ResponseWriter,status int,code string){writeJSON(w,status,map[string]string{"error":code})}
func signCanonical(key ed25519.PrivateKey,value any)(string,error){b,err:=canonicalJSON(value);if err!=nil{return "",err};return base64.StdEncoding.EncodeToString(ed25519.Sign(key,b)),nil}
func randomUUID() string { b:=make([]byte,16);_,_=rand.Read(b);b[6]=(b[6]&0x0f)|0x40;b[8]=(b[8]&0x3f)|0x80;h:=fmt.Sprintf("%x",b);return h[:8]+"-"+h[8:12]+"-"+h[12:16]+"-"+h[16:20]+"-"+h[20:] }
func canonicalJSON(v any)([]byte,error){raw,err:=json.Marshal(v);if err!=nil{return nil,err};var x any;d:=json.NewDecoder(strings.NewReader(string(raw)));d.UseNumber();if err=d.Decode(&x);err!=nil{return nil,err};return canonicalValue(x)}
func canonicalValue(v any)([]byte,error){switch x:=v.(type){case map[string]any:
	keys:=make([]string,0,len(x));for k:=range x{keys=append(keys,k)};sortStrings(keys);var b strings.Builder;b.WriteByte('{');for i,k:=range keys{if i>0{b.WriteByte(',')};kb,_:=json.Marshal(k);vb,e:=canonicalValue(x[k]);if e!=nil{return nil,e};b.Write(kb);b.WriteByte(':');b.Write(vb)};b.WriteByte('}');return []byte(b.String()),nil
	case []any:var b strings.Builder;b.WriteByte('[');for i,a:=range x{if i>0{b.WriteByte(',')};z,e:=canonicalValue(a);if e!=nil{return nil,e};b.Write(z)};b.WriteByte(']');return []byte(b.String()),nil
	default:return json.Marshal(v)}}
func sortStrings(a []string){for i:=1;i<len(a);i++{for j:=i;j>0&&a[j]<a[j-1];j--{a[j],a[j-1]=a[j-1],a[j]}}}
