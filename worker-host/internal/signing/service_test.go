package signing

import (
	"archive/zip"
	"crypto/tls"
	"crypto/sha256"
	"encoding/hex"
	"crypto/x509"
	"net/http/httptest"
	"strings"
	"os"
	"path/filepath"
	"testing"
)

func makeOTA(t *testing.T,entries map[string]string)string{
	t.Helper();file:=filepath.Join(t.TempDir(),"ota.zip");f,err:=os.Create(file);if err!=nil{t.Fatal(err)}
	z:=zip.NewWriter(f);for name,value:=range entries{w,err:=z.Create(name);if err!=nil{t.Fatal(err)};if _,err:=w.Write([]byte(value));err!=nil{t.Fatal(err)}}
	if err:=z.Close();err!=nil{t.Fatal(err)};if err:=f.Close();err!=nil{t.Fatal(err)};return file
}
func TestVerifyOTARequiresAndroidPayload(t *testing.T){
	file:=makeOTA(t,map[string]string{"payload.bin":"payload","META-INF/com/android/metadata":"ota"})
	if err:=verifyOTA(file,false);err!=nil{t.Fatal(err)}
}
func TestVerifyOTARejectsTraversalAndSymlinks(t *testing.T){
	file:=makeOTA(t,map[string]string{"../escape":"x","payload.bin":"payload"})
	if err:=verifyOTA(file,false);err==nil{t.Fatal("expected traversal rejection")}
	file=filepath.Join(t.TempDir(),"link.zip");f,err:=os.Create(file);if err!=nil{t.Fatal(err)}
	z:=zip.NewWriter(f);h:=&zip.FileHeader{Name:"META-INF/link"};h.SetMode(os.ModeSymlink|0777);w,err:=z.CreateHeader(h);if err!=nil{t.Fatal(err)};_,_=w.Write([]byte("/etc/passwd"));w,err=z.Create("payload.bin");if err!=nil{t.Fatal(err)};_,_=w.Write([]byte("payload"));_ = z.Close();_ = f.Close()
	if err:=verifyOTA(file,false);err==nil{t.Fatal("expected symlink entry rejection")}
}
func TestVerifyOTARequiresJARSignatureEntriesAfterSigning(t *testing.T){
	file:=makeOTA(t,map[string]string{"payload.bin":"payload","META-INF/MANIFEST.MF":"manifest","META-INF/CERT.SF":"sf","META-INF/CERT.RSA":"rsa"})
	if err:=verifyOTA(file,true);err!=nil{t.Fatal(err)}
	unsigned:=makeOTA(t,map[string]string{"payload.bin":"payload"})
	if err:=verifyOTA(unsigned,true);err==nil{t.Fatal("expected unsigned OTA rejection")}
}

func TestAuthorizationRequiresMutualTLSAndBearerToken(t *testing.T){
	rawCert:=[]byte("pinned platform client certificate");certHash:=sha256.Sum256(rawCert)
	s:=&Service{cfg:Config{BearerToken:strings.Repeat("s",40),ClientCertSHA256:hex.EncodeToString(certHash[:])}}
	r:=httptest.NewRequest("POST","/v1/sign",nil);r.Header.Set("Authorization","Bearer "+s.cfg.BearerToken)
	if s.authorized(r){t.Fatal("request without client certificate must be rejected")}
	r.TLS=&tls.ConnectionState{PeerCertificates:[]*x509.Certificate{{Raw:rawCert}}}
	if !s.authorized(r){t.Fatal("valid mTLS identity and bearer token should be accepted")}
	r.Header.Set("Authorization","Bearer "+strings.Repeat("x",40))
	if s.authorized(r){t.Fatal("incorrect bearer token must be rejected")}
}
