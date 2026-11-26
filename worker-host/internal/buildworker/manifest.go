package buildworker

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
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
type pinnedProject struct {
	Name string `xml:"name,attr"`
	Path string `xml:"path,attr"`
	Remote string `xml:"remote,attr"`
	Revision string `xml:"revision,attr"`
}
type localManifest struct { XMLName xml.Name `xml:"manifest"`; Projects []pinnedProject `xml:"project"` }
type pinnedSource struct { Kind string; URL string; SHA string; SourcePath string }

func normalizeRepoURL(raw string) string {
	raw = strings.TrimSuffix(raw, ".git")
	u, err := url.Parse(raw)
	if err != nil { return "" }
	u.Path = path.Clean(u.Path)
	return strings.TrimRight(u.String(), "/")
}

func snapshotSources(s Snapshot) []pinnedSource {
	out := []pinnedSource{{Kind:"device", URL:s.DeviceTree.RepositoryURL, SHA:s.DeviceTree.CommitSHA, SourcePath:s.DeviceTree.SourcePath}}
	for _,v := range s.SourceInputs { out=append(out,pinnedSource{Kind:v.SourceKind,URL:v.RepositoryURL,SHA:v.CommitSHA,SourcePath:v.SourcePath}) }
	seen:=map[string]bool{};dedup:=make([]pinnedSource,0,len(out))
	for _,v:=range out { key:=normalizeRepoURL(v.URL)+"@"+v.SHA; if !seen[key] { seen[key]=true;dedup=append(dedup,v) } }
	return dedup
}

// pinManifest pins sources already represented by the selected ROM manifest.
// Sources absent from that manifest are returned for immutable checkout and
// overlay into their canonical Android source-tree location.
func pinManifest(content string, s Snapshot) ([]byte, []pinnedSource, error) {
	var m manifestXML
	d:=xml.NewDecoder(strings.NewReader(content));d.Strict=true
	if err:=d.Decode(&m);err!=nil{return nil,nil,fmt.Errorf("parse embedded Android repo manifest: %w",err)}
	if m.XMLName.Local!="manifest"{return nil,nil,errors.New("embedded Android repo manifest root must be manifest")}
	remotes:=map[string]string{};for _,r:=range m.Remotes{remotes[r.Name]=r.Fetch}
	defaultRemote:=m.Default.Remote
	pins:=make([]pinnedProject,0);external:=make([]pinnedSource,0);seenPins:=map[string]bool{}
	for _,src:=range snapshotSources(s){
		target:=normalizeRepoURL(src.URL);if target==""{return nil,nil,errors.New("pinned repository URL is invalid")}
		found:=false
		for _,p:=range m.Projects{
			remote:=p.Remote;if remote==""{remote=defaultRemote}
			fetch,ok:=remotes[remote];if !ok{continue}
			projectURL:=normalizeRepoURL(strings.TrimRight(fetch,"/")+"/"+strings.TrimLeft(p.Name,"/"))
			if projectURL!=target{continue}
			projectPath:=p.Path;if projectPath==""{projectPath=p.Name}
			if !safeRelativePath(projectPath){return nil,nil,fmt.Errorf("manifest project %s has an unsafe path",p.Name)}
			key:=projectPath+"@"+src.SHA
			if !seenPins[key]{pins=append(pins,pinnedProject{Name:p.Name,Path:projectPath,Remote:remote,Revision:src.SHA});seenPins[key]=true}
			found=true
		}
		if !found{external=append(external,src)}
	}
	var out bytes.Buffer
	if len(pins)>0{
		enc:=xml.NewEncoder(&out);enc.Indent("","  ")
		if err:=enc.Encode(localManifest{Projects:pins});err!=nil{return nil,nil,err}
		if err:=enc.Flush();err!=nil{return nil,nil,err}
	}
	return out.Bytes(),external,nil
}
