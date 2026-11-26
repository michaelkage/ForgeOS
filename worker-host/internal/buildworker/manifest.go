package buildworker

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"strings"
)

type manifestXML struct {
	XMLName xml.Name `xml:"manifest"`
	Default struct { Remote string `xml:"remote,attr"` } `xml:"default"`
	Remotes []struct { Name string `xml:"name,attr"`; Fetch string `xml:"fetch,attr"` } `xml:"remote"`
	Projects []manifestProject `xml:"project"`
}
type manifestProject struct {
	Name string `xml:"name,attr"`
	Path string `xml:"path,attr"`
	Remote string `xml:"remote,attr"`
	Revision string `xml:"revision,attr"`
}
type pinnedProject struct { Name string `xml:"name,attr"`; Path string `xml:"path,attr"`; Remote string `xml:"remote,attr"`; Revision string `xml:"revision,attr"` }
type localManifest struct { XMLName xml.Name `xml:"manifest"`; Projects []pinnedProject `xml:"project"` }

func normalizeRepoURL(raw string) string {
	raw=strings.TrimSuffix(raw,".git")
	u,err:=url.Parse(raw);if err!=nil{return ""}
	u.Path=path.Clean(u.Path)
	return strings.TrimRight(u.String(),"/")
}
func pinManifest(content string,s Snapshot)([]byte,error){
	var m manifestXML
	d:=xml.NewDecoder(strings.NewReader(content));d.Strict=true
	if err:=d.Decode(&m);err!=nil{return nil,fmt.Errorf("parse embedded Android repo manifest: %w",err)}
	if m.XMLName.Local!="manifest"{return nil,errors.New("embedded Android repo manifest root must be manifest")}
	remotes:=map[string]string{};for _,r:=range m.Remotes{remotes[r.Name]=r.Fetch}
	defaultRemote:=m.Default.Remote
	type source struct{url,sha string}
	sources:=[]source{{s.DeviceTree.RepositoryURL,s.DeviceTree.CommitSHA}}
	for _,v:=range s.SourceInputs{sources=append(sources,source{v.RepositoryURL,v.CommitSHA})}
	pins:=make([]pinnedProject,0,len(sources));seen:=map[string]bool{}
	for _,src:=range sources{
		target:=normalizeRepoURL(src.url);if target==""{return nil,errors.New("pinned repository URL is invalid")}
		found:=false
		for _,p:=range m.Projects{
			remote:=p.Remote;if remote==""{remote=defaultRemote}
			fetch,ok:=remotes[remote];if !ok{continue}
			projectURL:=normalizeRepoURL(strings.TrimRight(fetch,"/")+"/"+strings.TrimLeft(p.Name,"/"))
			if projectURL!=target{continue}
			projectPath:=p.Path;if projectPath==""{projectPath=p.Name}
			key:=projectPath+"@"+src.sha
			if !seen[key]{pins=append(pins,pinnedProject{Name:p.Name,Path:projectPath,Remote:remote,Revision:src.sha});seen[key]=true}
			found=true
		}
		if !found{return nil,fmt.Errorf("pinned source repository %s is not present in the embedded repo manifest",src.url)}
	}
	if len(pins)==0{return nil,errors.New("no pinned projects were resolved from the snapshot")}
	var out bytes.Buffer;enc:=xml.NewEncoder(&out);enc.Indent("","  ")
	if err:=enc.Encode(localManifest{Projects:pins});err!=nil{return nil,err}
	if err:=enc.Flush();err!=nil{return nil,err}
	if _,err:=io.Copy(io.Discard,bytes.NewReader(out.Bytes()));err!=nil{return nil,err}
	return out.Bytes(),nil
}
