package signing

import (
	"strings"
	"testing"
	"time"
)

func validConfig()Config{return Config{Listen:"127.0.0.1:9444",TLSCertPath:"/etc/forgeos/tls.crt",TLSKeyPath:"/etc/forgeos/tls.key",ClientCAPath:"/etc/forgeos/clients.pem",BearerToken:strings.Repeat("x",40),JavaPath:"/usr/bin/java",JarSignerPath:"/usr/bin/jarsigner",SignAPKJar:"/opt/forgeos/signapk.jar",SignAPKJarSHA256:strings.Repeat("a",64),CertificateSHA256:strings.Repeat("b",64),PrivateKeySHA256:strings.Repeat("c",64),CertificatePath:"/etc/forgeos/release.x509.pem",PrivateKeyPath:"/etc/forgeos/release.pk8",WorkDir:"/var/lib/forgeos-signing",MaxArtifactBytes:20*1024*1024*1024,SignTimeout:time.Hour}}
func TestConfigAcceptsPrivateListener(t *testing.T){if err:=validConfig().Validate();err!=nil{t.Fatal(err)}}
func TestConfigRejectsPublicAndUnspecifiedListeners(t *testing.T){
	for _,address:=range []string{"0.0.0.0:9444","[::]:9444","8.8.8.8:9444","signer.example:9444"}{c:=validConfig();c.Listen=address;if err:=c.Validate();err==nil{t.Fatalf("expected listener %q to be rejected",address)}}
}
func TestConfigRejectsWeakTokenAndOversizedPolicy(t *testing.T){
	c:=validConfig();c.BearerToken="short";if err:=c.Validate();err==nil{t.Fatal("expected weak token rejection")}
	c=validConfig();c.MaxArtifactBytes=21*1024*1024*1024;if err:=c.Validate();err==nil{t.Fatal("expected artifact limit rejection")}
}
