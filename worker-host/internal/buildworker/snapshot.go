package buildworker

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
)

var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var commitPattern = regexp.MustCompile(`^[a-fA-F0-9]{40}package buildworker

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
)

var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
)
var githubPartPattern = regexp.MustCompile("^[A-Za-z0-9_.-]+$")
var codenamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{1,63}$`)
var branchPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$`)

type Snapshot struct {
	SchemaVersion int `json:"schemaVersion"`
	Configuration struct {
		ID string `json:"id"`
		Name string `json:"name"`
		ROMBase string `json:"romBase"`
		RootMethod string `json:"rootMethod"`
		ManifestRevision string `json:"manifestRevision"`
		Options struct {
			IncludeGapps bool `json:"includeGapps"`
			IncludeMicroG bool `json:"includeMicroG"`
			DebloatPackages []string `json:"debloatPackages"`
			FeatureFlags map[string]bool `json:"featureFlags"`
		} `json:"options"`
	} `json:"configuration"`
	Device struct {
		ID string `json:"id"`
		Codename string `json:"codename"`
		Architecture string `json:"architecture"`
		Manufacturer string `json:"manufacturer"`
		Model string `json:"model"`
	} `json:"device"`
	Manifest struct {
		Path string `json:"path"`
		Branch string `json:"branch"`
		SHA256 string `json:"sha256"`
		Content string `json:"content"`
	} `json:"manifest"`
	DeviceTree struct {
		RepositoryURL string `json:"repositoryUrl"`
		Branch string `json:"branch"`
		SourcePath string `json:"sourcePath"`
		CommitSHA string `json:"commitSha"`
	} `json:"deviceTree"`
	SourceInputs []struct {
		SourceKind string `json:"sourceKind"`
		ROMBase *string `json:"romBase"`
		RepositoryURL string `json:"repositoryUrl"`
		Branch string `json:"branch"`
		SourcePath string `json:"sourcePath"`
		CommitSHA string `json:"commitSha"`
	} `json:"sourceInputs"`
	ValidationReport json.RawMessage `json:"validationReport"`
	ConfigurationUpdatedAt json.RawMessage `json:"configurationUpdatedAt"`
}

func canonicalJSON(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil { return nil, err }
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF { return nil, errors.New("snapshot has trailing JSON data") }
	return canonicalValue(value)
}
func canonicalValue(v any) ([]byte,error) {
	switch x:=v.(type) {
	case map[string]any:
		keys:=make([]string,0,len(x));for k:=range x{keys=append(keys,k)};sort.Strings(keys)
		var b bytes.Buffer;b.WriteByte('{')
		for i,k:=range keys{if i>0{b.WriteByte(',')};kb,_:=json.Marshal(k);vb,e:=canonicalValue(x[k]);if e!=nil{return nil,e};b.Write(kb);b.WriteByte(':');b.Write(vb)}
		b.WriteByte('}');return b.Bytes(),nil
	case []any:
		var b bytes.Buffer;b.WriteByte('[');for i,a:=range x{if i>0{b.WriteByte(',')};z,e:=canonicalValue(a);if e!=nil{return nil,e};b.Write(z)};b.WriteByte(']');return b.Bytes(),nil
	default:return json.Marshal(v)
	}
}
func ParseSnapshot(raw []byte, expected string) (Snapshot,error) {
	var s Snapshot
	if !digestPattern.MatchString(expected){return s,errors.New("expected snapshot digest is invalid")}
	canonical,err:=canonicalJSON(raw);if err!=nil{return s,fmt.Errorf("canonicalize snapshot: %w",err)}
	sum:=sha256.Sum256(canonical);if hex.EncodeToString(sum[:])!=expected{return s,errors.New("immutable snapshot SHA-256 mismatch")}
	dec:=json.NewDecoder(bytes.NewReader(raw));dec.DisallowUnknownFields()
	if err:=dec.Decode(&s);err!=nil{return s,fmt.Errorf("decode immutable snapshot: %w",err)}
	if s.SchemaVersion!=1{return s,errors.New("unsupported build snapshot schema")}
	if s.Configuration.ID==""||s.Device.ID==""||!codenamePattern.MatchString(s.Device.Codename){return s,errors.New("snapshot device or configuration identity is invalid")}
	if s.Configuration.ROMBase!="lineage"&&s.Configuration.ROMBase!="crdroid"{return s,errors.New("unsupported ROM base")}
	if s.Configuration.ManifestRevision==""{s.Configuration.ManifestRevision=s.Manifest.Branch}
	if !validGitRef(s.Configuration.ManifestRevision){return s,errors.New("manifest revision must be an explicit valid branch or tag")}
	if !validGitRef(s.Manifest.Branch){return s,errors.New("device manifest branch is invalid")}
	if s.Configuration.RootMethod!="none"{return s,fmt.Errorf("root method %q is not supported by this build-worker release",s.Configuration.RootMethod)}
	if s.Configuration.Options.IncludeGapps||s.Configuration.Options.IncludeMicroG||len(s.Configuration.Options.DebloatPackages)>0{return s,errors.New("GApps, microG, and debloat options are not supported by this build-worker release")}
	for name,enabled:=range s.Configuration.Options.FeatureFlags{if enabled{return s,fmt.Errorf("feature flag %q is not supported by this build-worker release",name)}}
	if s.Device.Architecture!="arm64"&&s.Device.Architecture!="arm"&&s.Device.Architecture!="x86_64"{return s,errors.New("unsupported target architecture")}
	expectedManifest:="default.xml";if s.Configuration.ROMBase=="crdroid"{expectedManifest="snippets/crdroid.xml"}
	if s.Manifest.Path!=expectedManifest||s.Manifest.Branch==""||len(s.Manifest.Content)==0||len(s.Manifest.Content)>2*1024*1024{return s,errors.New("manifest snapshot does not match the selected ROM base or size policy")}
	manifestHash:=sha256.Sum256([]byte(s.Manifest.Content));if hex.EncodeToString(manifestHash[:])!=s.Manifest.SHA256{return s,errors.New("embedded manifest content digest mismatch")}
	if len(s.SourceInputs)>100{return s,errors.New("too many pinned source inputs")}
	for _,src:=range s.SourceInputs{if !commitPattern.MatchString(src.CommitSHA)||!validGitHubURL(src.RepositoryURL)||!validGitRef(src.Branch)||!safeRelativePath(src.SourcePath){return s,errors.New("pinned source identity is invalid")}}
	if !commitPattern.MatchString(s.DeviceTree.CommitSHA)||!validGitHubURL(s.DeviceTree.RepositoryURL)||!validGitRef(s.DeviceTree.Branch)||!safeRelativePath(s.DeviceTree.SourcePath){return s,errors.New("device tree source identity is invalid")}
	return s,nil
}

func validGitRef(value string)bool{
	if !branchPattern.MatchString(value)||strings.Contains(value,"..")||strings.Contains(value,"//")||strings.Contains(value,"@{")||strings.HasSuffix(value,"/")||strings.HasSuffix(value,"."){return false}
	for _,part:=range strings.Split(value,"/"){if strings.HasSuffix(part,".lock"){return false}}
	return true
}
func safeRelativePath(value string)bool{
	if value==""{return true}
	if len(value)>512||strings.HasPrefix(value,"/")||strings.Contains(value,"\\")||path.Clean(value)!=value||value=="."||value==".."||strings.HasPrefix(value,"../"){return false}
	for _,r:=range value{if r<0x20||r==0x7f{return false}}
	return true
}
func validGitHubURL(value string)bool{
	u,err:=url.Parse(value);if err!=nil||u.Scheme!="https"||u.Host!="github.com"||u.User!=nil||u.RawQuery!=""||u.Fragment!=""{return false}
	parts:=strings.Split(strings.Trim(u.Path,"/"),"/")
	return len(parts)==2&&githubPartPattern.MatchString(parts[0])&&githubPartPattern.MatchString(parts[1])&&!strings.Contains(parts[0],"..")&&!strings.Contains(parts[1],"..")
}
