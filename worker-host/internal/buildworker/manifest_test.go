package buildworker

import (
	"encoding/xml"
	"strings"
	"testing"
)

func TestPinManifestUsesImmutableSourceCommit(t *testing.T){
	s:=Snapshot{}
	s.DeviceTree.RepositoryURL="https://github.com/LineageOS/android_device_test_device"
	s.DeviceTree.CommitSHA="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	manifest:=`<manifest><remote name="github" fetch="https://github.com/"/><default remote="github"/><project name="LineageOS/android_device_test_device" path="device/test/device" revision="lineage-22.2"/></manifest>`
	got,err:=pinManifest(manifest,s);if err!=nil{t.Fatal(err)}
	var decoded struct{Projects []struct{Name string `xml:"name,attr"`;Path string `xml:"path,attr"`;Revision string `xml:"revision,attr"`} `xml:"project"`}
	if err:=xml.Unmarshal(got,&decoded);err!=nil{t.Fatal(err)}
	if len(decoded.Projects)!=1||decoded.Projects[0].Revision!=s.DeviceTree.CommitSHA||decoded.Projects[0].Path!="device/test/device"{t.Fatalf("unexpected pinned manifest: %s",got)}
}
func TestPinManifestRejectsUnreferencedPinnedRepository(t *testing.T){
	s:=Snapshot{};s.DeviceTree.RepositoryURL="https://github.com/LineageOS/not_in_manifest";s.DeviceTree.CommitSHA="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	manifest:=`<manifest><remote name="github" fetch="https://github.com/"/><default remote="github"/><project name="LineageOS/android_device_test_device" path="device/test/device"/></manifest>`
	if _,err:=pinManifest(manifest,s);err==nil||!strings.Contains(err.Error(),"not present"){t.Fatalf("expected missing pinned source error, got %v",err)}
}
