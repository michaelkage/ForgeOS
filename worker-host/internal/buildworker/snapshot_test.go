package buildworker

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func validSnapshot()map[string]any{
	manifest:=`<?xml version="1.0"?><manifest><remote name="github" fetch="https://github.com/"/><default remote="github"/><project name="LineageOS/android_device_test_device" path="device/test/device"/></manifest>`
	sum:=sha256.Sum256([]byte(manifest))
	return map[string]any{
		"schemaVersion":1,
		"configuration":map[string]any{"id":"123e4567-e89b-42d3-a456-426614174000","name":"Test","romBase":"lineage","rootMethod":"none","manifestRevision":"lineage-22.2","options":map[string]any{"includeGapps":false,"includeMicroG":false,"debloatPackages":[]string{},"featureFlags":map[string]bool{}}},
		"device":map[string]any{"id":"123e4567-e89b-42d3-a456-426614174001","codename":"test_device","manufacturer":"Test","model":"Device","architecture":"arm64"},
		"manifest":map[string]any{"path":"default.xml","branch":"lineage-22.2","sha256":hex.EncodeToString(sum[:]),"content":manifest},
		"deviceTree":map[string]any{"repositoryUrl":"https://github.com/LineageOS/android_device_test_device","branch":"lineage-22.2","sourcePath":"","commitSha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		"sourceInputs":[]any{},
		"validationReport":map[string]any{"valid":true},
		"configurationUpdatedAt":"2026-11-26T12:00:00.000Z",
	}
}
func snapshotBytes(t *testing.T,v any)[]byte{t.Helper();b,e:=json.Marshal(v);if e!=nil{t.Fatal(e)};return b}
func snapshotDigest(t *testing.T,b []byte)string{t.Helper();c,e:=canonicalJSON(b);if e!=nil{t.Fatal(e)};sum:=sha256.Sum256(c);return hex.EncodeToString(sum[:])}

func TestParseSnapshotAcceptsCanonicalImmutableSnapshot(t *testing.T){
	raw:=snapshotBytes(t,validSnapshot());got,err:=ParseSnapshot(raw,snapshotDigest(t,raw));if err!=nil{t.Fatal(err)}
	if got.Device.Codename!="test_device"||got.Configuration.ROMBase!="lineage"{t.Fatalf("unexpected snapshot: %#v",got)}
}
func TestParseSnapshotRejectsDigestMismatch(t *testing.T){
	raw:=snapshotBytes(t,validSnapshot());if _,err:=ParseSnapshot(raw,"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");err==nil{t.Fatal("expected digest mismatch")}
}
func TestParseSnapshotRejectsUnsupportedRootAndBuildOptions(t *testing.T){
	for _,mutate:=range []func(map[string]any){
		func(v map[string]any){v["configuration"].(map[string]any)["rootMethod"]="magisk"},
		func(v map[string]any){v["configuration"].(map[string]any)["options"].(map[string]any)["includeGapps"]=true},
		func(v map[string]any){v["configuration"].(map[string]any)["options"].(map[string]any)["featureFlags"]=map[string]bool{"experimental":true}},
	}{
		v:=validSnapshot();mutate(v);raw:=snapshotBytes(t,v)
		if _,err:=ParseSnapshot(raw,snapshotDigest(t,raw));err==nil{t.Fatal("expected unsupported build configuration rejection")}
	}
}
