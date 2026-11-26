package buildworker

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

type Config struct { SnapshotPath string; ExpectedSHA256 string; ArtifactPath string }
type lockedProject struct { Path string `json:"path"`; Name string `json:"name"`; Revision string `json:"revision"` }
type sourceLockfile struct { SchemaVersion int `json:"schemaVersion"`; Projects []lockedProject `json:"projects"` }
var safeArtifactName=regexp.MustCompile(`(?i)\.zip$`)
const lineageManifestURL="https://github.com/LineageOS/android.git"
const crdroidManifestURL="https://github.com/crdroidandroid/android.git"

func Run(ctx context.Context,cfg Config)error{
	raw,err:=os.ReadFile(cfg.SnapshotPath);if err!=nil{return fmt.Errorf("read snapshot: %w",err)}
	s,err:=ParseSnapshot(raw,cfg.ExpectedSHA256);if err!=nil{return err}
	workspace,err:=os.Getwd();if err!=nil{return err}
	workspace,err=filepath.Abs(workspace);if err!=nil{return err}
	if !filepath.IsAbs(cfg.ArtifactPath){return errors.New("artifact output path must be absolute")}
	artifact,err:=filepath.Abs(cfg.ArtifactPath);if err!=nil{return err}
	rel,err:=filepath.Rel(workspace,artifact);if err!=nil||rel==".."||strings.HasPrefix(rel,".."+string(os.PathSeparator)){return errors.New("artifact output must remain inside the encrypted job workspace")}
	if err:=os.MkdirAll(filepath.Dir(artifact),0700);err!=nil{return err}
	if _,err:=os.Stat(filepath.Join(workspace,"build","envsetup.sh"));err==nil{return errors.New("workspace already contains Android source; refusing to reuse non-empty source state")}
	manifestURL:=lineageManifestURL;if s.Configuration.ROMBase=="crdroid"{manifestURL=crdroidManifestURL}
	manifestArgs:=[]string{"init","-u",manifestURL,"-b",s.Configuration.ManifestRevision,"-m",s.Manifest.Path,"--depth=1","--no-clone-bundle"}
	if err:=run(ctx,workspace,30*time.Minute,"/usr/local/bin/repo",manifestArgs...);err!=nil{return fmt.Errorf("repo init: %w",err)}
	manifestPath:=filepath.Join(workspace,".repo","manifests",filepath.FromSlash(s.Manifest.Path))
	if err:=os.MkdirAll(filepath.Dir(manifestPath),0700);err!=nil{return err}
	if err:=os.WriteFile(manifestPath,[]byte(s.Manifest.Content),0600);err!=nil{return err}
	manifest,externalSources,err:=pinManifest(s.Manifest.Content,s);if err!=nil{return err}
	if len(manifest)>0{
		if err:=os.MkdirAll(filepath.Join(workspace,".repo","local_manifests"),0700);err!=nil{return err}
		if err:=os.WriteFile(filepath.Join(workspace,".repo","local_manifests","forgeos-pinned.xml"),manifest,0600);err!=nil{return err}
	}
	jobs:=fmt.Sprintf("%d",max(2,min(16,runtime.NumCPU())))
	if err:=run(ctx,workspace,ctxDeadlineBudget(ctx),"/usr/local/bin/repo","sync","-c","--fail-fast","--force-sync","--no-clone-bundle","--no-tags","-j",jobs);err!=nil{return fmt.Errorf("repo sync: %w",err)}
	if err:=checkoutExternalSources(ctx,workspace,s,externalSources);err!=nil{return fmt.Errorf("stage pinned device, kernel, and vendor sources: %w",err)}
	lockfile,err:=captureSourceLockfile(ctx,workspace,s,externalSources)
	if err!=nil{return fmt.Errorf("capture immutable Android source revisions: %w",err)}
	lockfileBytes,err:=json.Marshal(lockfile);if err!=nil{return err}
	if err:=os.WriteFile(filepath.Join(workspace,"source-lockfile.json"),lockfileBytes,0400);err!=nil{return err}
	target:="lineage_"+s.Device.Codename+"-userdebug"
	script:="set -euo pipefail; source build/envsetup.sh; lunch \"$1\"; mka bacon"
	if err:=run(ctx,workspace,ctxDeadlineBudget(ctx),"/bin/bash","-lc",script,"forgeos-build-worker",target);err!=nil{return fmt.Errorf("Android ROM build: %w",err)}
	outputDir:=filepath.Join(workspace,"out","target","product",s.Device.Codename)
	entries,err:=os.ReadDir(outputDir);if err!=nil{return fmt.Errorf("read Android output directory: %w",err)}
	var candidates []string
	for _,entry:=range entries{if entry.IsDir()||!safeArtifactName.MatchString(entry.Name()){continue};lower:=strings.ToLower(entry.Name());if strings.Contains(lower,s.Device.Codename)&&!strings.Contains(lower,"target_files"){candidates=append(candidates,filepath.Join(outputDir,entry.Name()))}}
	sort.Strings(candidates)
	if len(candidates)!=1{return fmt.Errorf("expected exactly one flashable ZIP for %s, found %d",s.Device.Codename,len(candidates))}
	if err:=verifyFlashableZIP(candidates[0]);err!=nil{return err}
	if err:=copyFile(candidates[0],artifact);err!=nil{return err}
	return verifyFlashableZIP(artifact)
}

func captureSourceLockfile(ctx context.Context,workspace string,s Snapshot,external []pinnedSource)(sourceLockfile,error){
	out:=sourceLockfile{SchemaVersion:1,Projects:make([]lockedProject,0,512)}
	cmdCtx,cancel:=context.WithTimeout(ctx,10*time.Minute);defer cancel()
	cmd:=exec.CommandContext(cmdCtx,"/usr/local/bin/repo","forall","-c",`printf '%s\t%s\t%s\n' "$REPO_PATH" "$REPO_PROJECT" "$(git rev-parse --verify HEAD)"`)
	cmd.Dir=workspace
	cmd.Env=[]string{"PATH=/usr/local/bin:/usr/bin:/bin","HOME=/workspace/forgeos","TMPDIR=/tmp","LANG=C.UTF-8","LC_ALL=C.UTF-8","GIT_TERMINAL_PROMPT=0","GIT_CONFIG_NOSYSTEM=1","GIT_CONFIG_GLOBAL=/dev/null"}
	var stdout,stderr bytes.Buffer
	cmd.Stdout=&stdout;cmd.Stderr=&stderr
	if err:=cmd.Run();err!=nil{return out,fmt.Errorf("repo forall failed: %w",err)}
	if stdout.Len()>2*1024*1024{return out,errors.New("source lockfile command output exceeds 2 MiB")}
	seen:=make(map[string]struct{})
	for _,line:=range strings.Split(strings.TrimSpace(stdout.String()),"\n"){
		if line==""{continue}
		fields:=strings.Split(line,"\t")
		if len(fields)!=3||!safeRelativePath(fields[0])||fields[0]==""||fields[1]==""||!commitPattern.MatchString(fields[2]){return out,errors.New("repo forall returned an invalid project identity")}
		if _,ok:=seen[fields[0]];ok{return out,fmt.Errorf("duplicate Android source path %q",fields[0])}
		seen[fields[0]]=struct{}{}
		out.Projects=append(out.Projects,lockedProject{Path:fields[0],Name:fields[1],Revision:strings.ToLower(fields[2])})
		if len(out.Projects)>2000{return out,errors.New("Android source project count exceeds 2000")}
	}
	for _,source:=range external{
		destination,err:=sourceDestination(source,s.Device.Codename);if err!=nil{return out,err}
		if _,ok:=seen[destination];ok{return out,fmt.Errorf("external pinned source collides with synced project path %q",destination)}
		seen[destination]=struct{}{}
		out.Projects=append(out.Projects,lockedProject{Path:destination,Name:source.URL,Revision:strings.ToLower(source.SHA)})
	}
	sort.Slice(out.Projects,func(i,j int)bool{return out.Projects[i].Path<out.Projects[j].Path})
	if len(out.Projects)==0{return out,errors.New("repo sync produced an empty source lockfile")}
	return out,nil
}

func ctxDeadlineBudget(ctx context.Context)time.Duration{if d,ok:=ctx.Deadline();ok{return time.Until(d)};return 2*time.Hour}
func run(ctx context.Context,dir string,timeout time.Duration,binary string,args ...string)error{
	if timeout<=0{return errors.New("build command deadline has expired")}
	cmdCtx,cancel:=context.WithTimeout(ctx,timeout);defer cancel()
	cmd:=exec.CommandContext(cmdCtx,binary,args...);cmd.Dir=dir
	cmd.Env=[]string{"PATH=/usr/local/bin:/usr/bin:/bin","HOME=/workspace/forgeos","TMPDIR=/tmp","LANG=C.UTF-8","LC_ALL=C.UTF-8","GIT_TERMINAL_PROMPT=0","GIT_CONFIG_NOSYSTEM=1","GIT_CONFIG_GLOBAL=/dev/null","USE_CCACHE=1","CCACHE_DIR=/workspace/ccache"}
	logPath:=filepath.Join(dir,"forgeos-build.log")
	logFile,err:=os.OpenFile(logPath,os.O_CREATE|os.O_APPEND|os.O_WRONLY,0600);if err!=nil{return err};defer logFile.Close()
	cmd.Stdout=logFile;cmd.Stderr=logFile
	if err:=cmd.Run();err!=nil{
		if cmdCtx.Err()!=nil{return fmt.Errorf("%s exceeded its deadline",filepath.Base(binary))}
		return fmt.Errorf("%s failed: %w (log: %s)",filepath.Base(binary),err,logPath)
	}
	return nil
}
func copyFile(source,destination string)error{
	in,err:=os.Open(source);if err!=nil{return err};defer in.Close()
	tmp:=destination+".partial";out,err:=os.OpenFile(tmp,os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600);if err!=nil{return err}
	_,copyErr:=io.Copy(out,in);syncErr:=out.Sync();closeErr:=out.Close()
	if copyErr!=nil{_ = os.Remove(tmp);return copyErr};if syncErr!=nil{_ = os.Remove(tmp);return syncErr};if closeErr!=nil{_ = os.Remove(tmp);return closeErr}
	if err:=os.Rename(tmp,destination);err!=nil{_ = os.Remove(tmp);return err};return nil
}
func verifyFlashableZIP(file string)error{
	st,err:=os.Lstat(file);if err!=nil{return err};if !st.Mode().IsRegular()||st.Mode()&os.ModeSymlink!=0||st.Size()<1024||st.Size()>20*1024*1024*1024{return errors.New("build output ZIP has an invalid file type or size")}
	zr,err:=zip.OpenReader(file);if err!=nil{return fmt.Errorf("build output is not a valid ZIP archive: %w",err)};defer zr.Close()
	if len(zr.File)==0||len(zr.File)>200000{return errors.New("build output ZIP entry count is outside policy")}
	payload,updater:=false,false
	for _,f:=range zr.File{
		name:=strings.ReplaceAll(f.Name,"\\","/");trimmed:=strings.TrimSuffix(name,"/");clean:=path.Clean(trimmed)
		if strings.HasPrefix(name,"/")||clean==".."||strings.HasPrefix(clean,"../")||strings.Contains(name,":")||clean!=trimmed{return errors.New("build output ZIP contains an unsafe entry path")}
		if f.Mode()&os.ModeSymlink!=0{return errors.New("build output ZIP contains a symbolic link entry")}
		if name=="payload.bin"{payload=true}
		if name=="META-INF/com/google/android/update-binary"{updater=true}
	}
	if !payload&&!updater{return errors.New("build output ZIP does not contain an Android OTA payload or recovery updater")}
	return nil
}
