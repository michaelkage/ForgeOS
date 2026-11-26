package buildworker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"time"
)

func sourceDestination(source pinnedSource, codename string) (string,error) {
	u,err:=url.Parse(source.URL);if err!=nil{return "",errors.New("invalid pinned source URL")}
	repo:=strings.TrimSuffix(path.Base(u.Path),".git")
	switch source.Kind {
	case "device":
		const prefix="android_device_"
		if !strings.HasPrefix(repo,prefix){return "",fmt.Errorf("device source repository %q must use the android_device_<manufacturer>_<codename> naming convention",repo)}
		parts:=strings.SplitN(strings.TrimPrefix(repo,prefix),"_",2)
		if len(parts)!=2||parts[1]!=codename{return "",errors.New("device source repository does not match the configured manufacturer/codename path")}
		return filepath.Join("device",parts[0],parts[1]),nil
	case "kernel":
		const prefix="android_kernel_"
		if !strings.HasPrefix(repo,prefix){return "",fmt.Errorf("kernel source repository %q must use the android_kernel_<manufacturer>_<platform> naming convention",repo)}
		parts:=strings.SplitN(strings.TrimPrefix(repo,prefix),"_",2)
		if len(parts)!=2{return "",errors.New("kernel source repository does not identify manufacturer and platform")}
		return filepath.Join("kernel",parts[0],parts[1]),nil
	case "vendor":
		suffix:=""
		for _,prefix:=range []string{"proprietary_vendor_","android_vendor_"}{if strings.HasPrefix(repo,prefix){suffix=strings.TrimPrefix(repo,prefix);break}}
		if suffix==""{return "",fmt.Errorf("vendor source repository %q must use a supported vendor repository naming convention",repo)}
		parts:=strings.SplitN(suffix,"_",2)
		if len(parts)==2{return filepath.Join("vendor",parts[0],parts[1]),nil}
		return filepath.Join("vendor",parts[0]),nil
	default:return "",fmt.Errorf("unsupported pinned source kind %q",source.Kind)
	}
}

func checkoutExternalSources(ctx context.Context,workspace string,s Snapshot,sources []pinnedSource)error{
	for i,source:=range sources{
		if err:=ctx.Err();err!=nil{return err}
		destination,err:=sourceDestination(source,s.Device.Codename);if err!=nil{return err}
		repositoryDir:=filepath.Join(workspace,".forgeos-sources",fmt.Sprintf("%03d",i))
		if err:=os.MkdirAll(filepath.Dir(repositoryDir),0700);err!=nil{return err}
		if err:=run(ctx,workspace,30*time.Minute,"git","clone","--no-checkout","--filter=blob:none","--no-tags","--",source.URL,repositoryDir);err!=nil{return fmt.Errorf("clone pinned %s source: %w",source.Kind,err)}
		if err:=run(ctx,workspace,30*time.Minute,"git","-C",repositoryDir,"fetch","--no-tags","--depth=1","origin",source.SHA);err!=nil{return fmt.Errorf("fetch pinned %s commit: %w",source.Kind,err)}
		if err:=run(ctx,workspace,30*time.Minute,"git","-C",repositoryDir,"checkout","--detach",source.SHA);err!=nil{return fmt.Errorf("checkout pinned %s commit: %w",source.Kind,err)}
		cmd:=exec.CommandContext(ctx,"git","-C",repositoryDir,"rev-parse","--verify","HEAD")
		cmd.Env=[]string{"PATH=/usr/local/bin:/usr/bin:/bin","GIT_CONFIG_NOSYSTEM=1","GIT_CONFIG_GLOBAL=/dev/null","GIT_TERMINAL_PROMPT=0"}
		head,err:=cmd.Output();if err!=nil||strings.TrimSpace(string(head))!=source.SHA{return fmt.Errorf("pinned %s checkout HEAD does not match the immutable snapshot",source.Kind)}
		sourceRoot:=repositoryDir
		if source.SourcePath!=""{sourceRoot=filepath.Join(repositoryDir,filepath.FromSlash(source.SourcePath))}
		sourceRoot,err=filepath.Abs(sourceRoot);if err!=nil{return err}
		repoAbs,err:=filepath.Abs(repositoryDir);if err!=nil{return err}
		rel,err:=filepath.Rel(repoAbs,sourceRoot);if err!=nil||rel==".."||strings.HasPrefix(rel,".."+string(os.PathSeparator)){return errors.New("pinned source path escapes its cloned repository")}
		st,err:=os.Stat(sourceRoot);if err!=nil||!st.IsDir(){return fmt.Errorf("pinned %s source path is not a directory",source.Kind)}
		target:=filepath.Join(workspace,destination)
		targetAbs,err:=filepath.Abs(target);if err!=nil{return err}
		workspaceAbs,err:=filepath.Abs(workspace);if err!=nil{return err}
		rel,err=filepath.Rel(workspaceAbs,targetAbs);if err!=nil||rel==".."||strings.HasPrefix(rel,".."+string(os.PathSeparator)){return errors.New("pinned source destination escapes the build workspace")}
		if _,err:=os.Lstat(targetAbs);err==nil{return fmt.Errorf("refusing to overwrite existing Android source path %s",destination)}else if !os.IsNotExist(err){return err}
		if err:=copySourceTree(sourceRoot,targetAbs);err!=nil{return fmt.Errorf("copy pinned %s source into %s: %w",source.Kind,destination,err)}
	}
	return nil
}

func copySourceTree(source,destination string)error{
	return filepath.WalkDir(source,func(current string,entry os.DirEntry,walkErr error)error{
		if walkErr!=nil{return walkErr}
		rel,err:=filepath.Rel(source,current);if err!=nil{return err}
		target:=destination;if rel!="."{target=filepath.Join(destination,rel)}
		info,err:=entry.Info();if err!=nil{return err}
		if info.Mode()&os.ModeSymlink!=0{return fmt.Errorf("source tree contains a symbolic link at %s",rel)}
		if entry.IsDir(){return os.MkdirAll(target,0755)}
		if !info.Mode().IsRegular(){return fmt.Errorf("source tree contains a non-regular file at %s",rel)}
		if err:=os.MkdirAll(filepath.Dir(target),0755);err!=nil{return err}
		in,err:=os.Open(current);if err!=nil{return err};defer in.Close()
		out,err:=os.OpenFile(target,os.O_CREATE|os.O_EXCL|os.O_WRONLY,info.Mode().Perm()&0755);if err!=nil{return err}
		_,copyErr:=io.Copy(out,in);syncErr:=out.Sync();closeErr:=out.Close()
		if copyErr!=nil{return copyErr};if syncErr!=nil{return syncErr};return closeErr
	})
}
