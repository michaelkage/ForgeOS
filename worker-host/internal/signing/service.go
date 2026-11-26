package signing

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
		"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
		"time"
)

var uuidPattern=regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var shaPattern=regexp.MustCompile(`^[a-f0-9]{64}$`)

type Service struct { cfg Config; ledger *ledger; mux *http.ServeMux; slots chan struct{} }
func NewService(cfg Config)(*Service,error){
	if err:=cfg.Validate();err!=nil{return nil,err}
	for _,p:=range []string{cfg.TLSCertPath,cfg.TLSKeyPath,cfg.ClientCAPath,cfg.SignAPKJar,cfg.CertificatePath,cfg.PrivateKeyPath,cfg.JavaPath,cfg.JarSignerPath}{if err:=verifyProtectedFile(p,p==cfg.PrivateKeyPath||p==cfg.TLSKeyPath,p==cfg.JavaPath||p==cfg.JarSignerPath);err!=nil{return nil,fmt.Errorf("verify signing dependency %s: %w",p,err)}}
	for _,item:=range []struct{path,want string}{{cfg.SignAPKJar,cfg.SignAPKJarSHA256},{cfg.CertificatePath,cfg.CertificateSHA256},{cfg.PrivateKeyPath,cfg.PrivateKeySHA256}}{got,_,err:=hashFile(item.path);if err!=nil{return nil,err};if got!=item.want{return nil,fmt.Errorf("pinned signing dependency digest mismatch: %s",item.path)}}
	if err:=os.MkdirAll(cfg.WorkDir,0700);err!=nil{return nil,err}
	st,err:=os.Lstat(cfg.WorkDir);if err!=nil{return nil,err};if !st.IsDir()||st.Mode()&os.ModeSymlink!=0||st.Mode().Perm()&0077!=0{return nil,errors.New("signing work directory must be a directory inaccessible to other users")}
	l,err:=openLedger(filepath.Join(cfg.WorkDir,"signing-ledger.jsonl"));if err!=nil{return nil,err}
	s:=&Service{cfg:cfg,ledger:l,mux:http.NewServeMux(),slots:make(chan struct{},1)}
	s.mux.HandleFunc("GET /healthz",s.health)
	s.mux.HandleFunc("POST /v1/sign",s.sign)
	return s,nil
}
func verifyProtectedFile(file string,private,executable bool)error{
	st,err:=os.Lstat(file);if err!=nil{return err}
	if !st.Mode().IsRegular()||st.Mode()&os.ModeSymlink!=0{return errors.New("must be a regular non-symlink file")}
	sys,ok:=st.Sys().(*syscall.Stat_t);if !ok||sys.Uid!=0{return errors.New("must be owned by root")}
	if st.Mode().Perm()&0022!=0{return errors.New("must not be group- or world-writable")}
	if private&&st.Mode().Perm()&0007!=0{return errors.New("private key must not be accessible to other users")}
	if executable&&st.Mode().Perm()&0111==0{return errors.New("required signing tool is not executable")}
	return nil
}
func(s *Service) TLSConfig()(*tls.Config,error){
	cert,err:=tls.LoadX509KeyPair(s.cfg.TLSCertPath,s.cfg.TLSKeyPath);if err!=nil{return nil,err}
	caPEM,err:=os.ReadFile(s.cfg.ClientCAPath);if err!=nil{return nil,err}
	pool:=x509.NewCertPool();if !pool.AppendCertsFromPEM(caPEM){return nil,errors.New("client CA bundle contains no valid certificates")}
	return &tls.Config{MinVersion:tls.VersionTLS13,Certificates:[]tls.Certificate{cert},ClientAuth:tls.RequireAndVerifyClientCert,ClientCAs:pool},nil
}
func(s *Service) Handler()http.Handler{return securityHeaders(s.mux)}
func(s *Service) Serve()error{
	tlsConfig,err:=s.TLSConfig();if err!=nil{return err}
	listener,err:=net.Listen("tcp",s.cfg.Listen);if err!=nil{return err}
	tlsListener:=tls.NewListener(listener,tlsConfig)
	server:=&http.Server{Handler:s.Handler(),ReadHeaderTimeout:10*time.Second,ReadTimeout:s.cfg.SignTimeout+5*time.Minute,IdleTimeout:60*time.Second,MaxHeaderBytes:16*1024}
	done:=make(chan error,1)
	go func(){done<-server.Serve(tlsListener)}()
	select{
	case <-ctx.Done():
		shutdownCtx,cancel:=context.WithTimeout(context.Background(),30*time.Second);defer cancel()
		_ = server.Shutdown(shutdownCtx)
		return nil
	case err:=<-done:
		if errors.Is(err,http.ErrServerClosed){return nil}
		return err
	}
}
func securityHeaders(next http.Handler)http.Handler{return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){w.Header().Set("Cache-Control","no-store");w.Header().Set("X-Content-Type-Options","nosniff");next.ServeHTTP(w,r)})}
func(s *Service) health(w http.ResponseWriter,r *http.Request){w.Header().Set("Content-Type","application/json");_,_=io.WriteString(w,`{"status":"ok"}`)}
func(s *Service) authorized(r *http.Request)bool{
	if r.TLS==nil||len(r.TLS.PeerCertificates)==0{return false}
	certDigest:=sha256.Sum256(r.TLS.PeerCertificates[0].Raw)
	expectedCert,err:=hex.DecodeString(s.cfg.ClientCertSHA256)
	if err!=nil||len(expectedCert)!=sha256.Size||subtle.ConstantTimeCompare(certDigest[:],expectedCert)!=1{return false}
	header:=r.Header.Get("Authorization");if !strings.HasPrefix(header,"Bearer "){return false}
	got:=[]byte(strings.TrimPrefix(header,"Bearer "));want:=[]byte(s.cfg.BearerToken)
	return len(got)==len(want)&&subtle.ConstantTimeCompare(got,want)==1
}
func(s *Service) sign(w http.ResponseWriter,r *http.Request){
	if !s.authorized(r){http.Error(w,"unauthorized",http.StatusUnauthorized);return}
	job:=r.Header.Get("X-ForgeOS-Job-ID");attempt,err:=strconv.Atoi(r.Header.Get("X-ForgeOS-Attempt"))
	snapshotSHA:=r.Header.Get("X-ForgeOS-Snapshot-SHA256");inputSHA:=r.Header.Get("X-ForgeOS-Artifact-SHA256")
	if !uuidPattern.MatchString(job)||err!=nil||attempt<1||attempt>20||!shaPattern.MatchString(snapshotSHA)||!shaPattern.MatchString(inputSHA){http.Error(w,"invalid signing request metadata",http.StatusBadRequest);return}
	if r.ContentLength<1||r.ContentLength>s.cfg.MaxArtifactBytes{http.Error(w,"artifact size outside policy",http.StatusRequestEntityTooLarge);return}
	if r.Header.Get("Content-Type")!="application/zip"{http.Error(w,"application/zip required",http.StatusUnsupportedMediaType);return}
	if existing,ok:=s.ledger.get(job,attempt);ok{
		if existing.SnapshotSHA256!=snapshotSHA||existing.InputSHA256!=inputSHA{http.Error(w,"job attempt already bound to different artifact metadata",http.StatusConflict);return}
		if existing.Status!="complete"{http.Error(w,"signing attempt is already reserved and requires operator recovery",http.StatusConflict);return}
		s.serveCached(w,r,existing);return
	}
	ctx,cancel:=context.WithTimeout(r.Context(),s.cfg.SignTimeout);defer cancel()
	select{case s.slots<-struct{}{}:defer func(){<-s.slots}();case <-ctx.Done():http.Error(w,"signing request cancelled",http.StatusRequestTimeout);return}
	input,err:=os.CreateTemp(s.cfg.WorkDir,"input-*.zip");if err!=nil{http.Error(w,"unable to allocate signing workspace",http.StatusInternalServerError);return}
	inputPath:=input.Name();defer os.Remove(inputPath)
	h:=sha256.New();limited:=io.LimitReader(r.Body,s.cfg.MaxArtifactBytes+1)
	n,copyErr:=io.Copy(io.MultiWriter(input,h),limited);syncErr:=input.Sync();closeErr:=input.Close()
	if copyErr!=nil||syncErr!=nil||closeErr!=nil||n<1||n>s.cfg.MaxArtifactBytes{http.Error(w,"artifact upload failed",http.StatusBadRequest);return}
	actual:=hex.EncodeToString(h.Sum(nil));if actual!=inputSHA{http.Error(w,"artifact digest mismatch",http.StatusUnprocessableEntity);return}
	if err:=verifyOTA(inputPath,false);err!=nil{http.Error(w,"input is not a valid flashable OTA ZIP",http.StatusUnprocessableEntity);return}
	reservation:=ledgerRecord{JobID:job,Attempt:attempt,SnapshotSHA256:snapshotSHA,InputSHA256:inputSHA}
	if err:=s.ledger.reserve(reservation);err!=nil{http.Error(w,"signing attempt reservation failed",http.StatusConflict);return}
	outputPath:=filepath.Join(s.cfg.WorkDir,"signed",job+"-"+strconv.Itoa(attempt)+".zip")
	if err:=os.MkdirAll(filepath.Dir(outputPath),0700);err!=nil{s.failReservation(reservation);http.Error(w,"signing workspace unavailable",http.StatusInternalServerError);return}
	partial:=outputPath+".partial"
	for _,candidate:=range []string{outputPath,partial}{if _,err:=os.Lstat(candidate);err==nil{s.failReservation(reservation);http.Error(w,"signing output path already exists; operator recovery is required",http.StatusConflict);return}else if !os.IsNotExist(err){s.failReservation(reservation);http.Error(w,"signing output path cannot be inspected",http.StatusInternalServerError);return}}
	if err:=s.runSign(ctx,inputPath,partial);err!=nil{s.failReservation(reservation);_ = os.Remove(partial);http.Error(w,"OTA signing failed",http.StatusUnprocessableEntity);return}
	if err:=verifyOTA(partial,true);err!=nil{s.failReservation(reservation);_ = os.Remove(partial);http.Error(w,"signed OTA verification failed",http.StatusUnprocessableEntity);return}
	outHash,outSize,err:=hashFile(partial);if err!=nil{s.failReservation(reservation);_ = os.Remove(partial);http.Error(w,"signed artifact verification failed",http.StatusInternalServerError);return}
	if outSize>s.cfg.MaxArtifactBytes{ s.failReservation(reservation);_ = os.Remove(partial);http.Error(w,"signed artifact exceeds size policy",http.StatusRequestEntityTooLarge);return }
	if err:=os.Rename(partial,outputPath);err!=nil{s.failReservation(reservation);_ = os.Remove(partial);http.Error(w,"signed artifact persistence failed",http.StatusInternalServerError);return}
	reservation.OutputSHA256=outHash;reservation.Status="complete"
	if err:=s.ledger.update(reservation);err!=nil{http.Error(w,"signing result could not be committed to the audit ledger",http.StatusInternalServerError);return}
	s.serveCached(w,r,reservation)
}
func(s *Service) failReservation(r ledgerRecord){r.Status="failed";_ = s.ledger.update(r)}
func(s *Service) runSign(ctx context.Context,input,output string)error{
	cmd:=exec.CommandContext(ctx,s.cfg.JavaPath,"-jar",s.cfg.SignAPKJar,"-w",s.cfg.CertificatePath,s.cfg.PrivateKeyPath,input,output)
	cmd.Env=[]string{"PATH=/usr/bin:/bin","HOME="+s.cfg.WorkDir,"LANG=C","LC_ALL=C"}
	logPath:=filepath.Join(s.cfg.WorkDir,"signapk.log")
	logFile,err:=os.OpenFile(logPath,os.O_CREATE|os.O_APPEND|os.O_WRONLY,0600);if err!=nil{return err};defer logFile.Close()
	cmd.Stdout=logFile;cmd.Stderr=logFile
	if err:=cmd.Run();err!=nil{return fmt.Errorf("signapk failed: %w",err)}
	verify:=exec.CommandContext(ctx,s.cfg.JarSignerPath,"-verify","-certs",output);verify.Env=cmd.Env
	verify.Stdout=logFile;verify.Stderr=logFile
	if err:=verify.Run();err!=nil{return fmt.Errorf("JAR signature verification failed: %w",err)}
	return nil
}
func(s *Service) serveCached(w http.ResponseWriter,r *http.Request,record ledgerRecord){
	file:=filepath.Join(s.cfg.WorkDir,"signed",record.JobID+"-"+strconv.Itoa(record.Attempt)+".zip")
	digest,size,err:=hashFile(file);if err!=nil||digest!=record.OutputSHA256{http.Error(w,"cached signed artifact failed integrity verification",http.StatusInternalServerError);return}
	w.Header().Set("Content-Type","application/zip");w.Header().Set("Content-Length",strconv.FormatInt(size,10));w.Header().Set("X-ForgeOS-Signed-SHA256",digest)
	f,err:=os.Open(file);if err!=nil{http.Error(w,"signed artifact unavailable",http.StatusInternalServerError);return};defer f.Close()
	_,_=io.Copy(w,f)
}
func verifyOTA(file string,requireSignature bool)error{
	zr,err:=zip.OpenReader(file);if err!=nil{return err};defer zr.Close()
	if len(zr.File)==0||len(zr.File)>200000{return errors.New("OTA ZIP entry count outside policy")}
	payload,updater,manifest,sf,rsa:=false,false,false,false,false
	for _,entry:=range zr.File{
		name:=strings.ReplaceAll(entry.Name,string(rune(92)),"/");trimmed:=strings.TrimSuffix(name,"/");clean:=path.Clean(trimmed)
		if strings.HasPrefix(name,"/")||clean==".."||strings.HasPrefix(clean,"../")||strings.Contains(name,":")||clean!=trimmed||entry.Mode()&os.ModeSymlink!=0{return errors.New("OTA ZIP contains an unsafe entry")}
		upper:=strings.ToUpper(name)
		if name=="payload.bin"{payload=true};if name=="META-INF/com/google/android/update-binary"{updater=true}
		if upper=="META-INF/MANIFEST.MF"{manifest=true};if strings.HasPrefix(upper,"META-INF/")&&strings.HasSuffix(upper,".SF"){sf=true};if strings.HasPrefix(upper,"META-INF/")&&(strings.HasSuffix(upper,".RSA")||strings.HasSuffix(upper,".EC")||strings.HasSuffix(upper,".DSA")){rsa=true}
	}
	if !payload&&!updater{return errors.New("OTA ZIP has no Android payload or recovery updater")}
	if requireSignature&&(!manifest||!sf||!rsa){return errors.New("signed OTA ZIP is missing JAR signature entries")}
	if !requireSignature&&(manifest||sf||rsa){return errors.New("input OTA must be unsigned before release signing")}
	return nil
}
func hashFile(file string)(string,int64,error){
	st,err:=os.Lstat(file);if err!=nil{return "",0,err};if !st.Mode().IsRegular()||st.Mode()&os.ModeSymlink!=0{return "",0,errors.New("artifact path is not a regular non-symlink file")}
	f,err:=os.Open(file);if err!=nil{return "",0,err};defer f.Close()
	h:=sha256.New();n,err:=io.Copy(h,f);if err!=nil{return "",n,err};return hex.EncodeToString(h.Sum(nil)),n,nil
}
