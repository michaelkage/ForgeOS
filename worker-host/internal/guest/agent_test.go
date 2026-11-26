//go:build linux

package guest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func signedEnvelope(t *testing.T,private ed25519.PrivateKey,p BootstrapPayload)[]byte{
	t.Helper()
	raw,err:=canonicalJSON(p);if err!=nil{t.Fatal(err)}
	env:=Envelope{Payload:p,Signature:base64.StdEncoding.EncodeToString(ed25519.Sign(private,raw))}
	b,err:=json.Marshal(env);if err!=nil{t.Fatal(err)}
	return b
}

func validPayload(now time.Time)BootstrapPayload{
	return BootstrapPayload{SchemaVersion:1,JobID:"123e4567-e89b-42d3-a456-426614174000",Attempt:2,Architecture:"x86_64",ImageDigest:"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",APIBaseURL:"https://forgeos.example",BootstrapCredential:"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",Nonce:"123e4567-e89b-42d3-a456-426614174001",IssuedAt:now.Add(-time.Second),ExpiresAt:now.Add(2*time.Minute),Resources:struct{CPUCores int `json:"cpuCores"`;MemoryMiB int `json:"memoryMiB"`;DiskGiB int `json:"diskGiB"`;ProcessLimit int `json:"processLimit"`;WallTimeSeconds int `json:"wallTimeSeconds"`}{CPUCores:4,MemoryMiB:8192,DiskGiB:200,ProcessLimit:2048,WallTimeSeconds:3600}}
}

func TestVerifyEnvelopeAcceptsValidSignedBootstrap(t *testing.T){
	pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
	now:=time.Now().UTC();raw:=signedEnvelope(t,priv,validPayload(now))
	got,err:=VerifyEnvelope(raw,pub,now);if err!=nil{t.Fatal(err)}
	if got.Payload.JobID!="123e4567-e89b-42d3-a456-426614174000"||got.API.Host!="forgeos.example"{t.Fatalf("unexpected verified bootstrap: %#v",got)}
}

func TestVerifyEnvelopeRejectsTampering(t *testing.T){
	pub,priv,_:=ed25519.GenerateKey(rand.Reader);now:=time.Now().UTC();p:=validPayload(now)
	raw:=signedEnvelope(t,priv,p)
	p.BootstrapCredential="BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	if _,err:=VerifyEnvelope(signedEnvelope(t,priv,p),pub,now);err==nil{t.Fatal("expected invalid signature")}
	_ = raw
}

func TestVerifyEnvelopeRejectsExpiredAndNonHTTPSPayloads(t *testing.T){
	pub,priv,_:=ed25519.GenerateKey(rand.Reader);now:=time.Now().UTC()
	expired:=validPayload(now);expired.ExpiresAt=now.Add(-time.Second)
	if _,err:=VerifyEnvelope(signedEnvelope(t,priv,expired),pub,now);err==nil{t.Fatal("expected expired bootstrap rejection")}
	invalid:=validPayload(now);invalid.APIBaseURL="http://forgeos.example"
	if _,err:=VerifyEnvelope(signedEnvelope(t,priv,invalid),pub,now);err==nil{t.Fatal("expected non-HTTPS endpoint rejection")}
}
