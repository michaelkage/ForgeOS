package signing

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Listen string
	TLSCertPath string
	TLSKeyPath string
	ClientCAPath string
	BearerToken string
	JavaPath string
	JarSignerPath string
	SignAPKJar string
	CertificatePath string
	PrivateKeyPath string
	WorkDir string
	MaxArtifactBytes int64
	SignTimeout time.Duration
}

func ConfigFromEnv() (Config,error) {
	c:=Config{
		Listen:os.Getenv("FORGEOS_SIGNING_LISTEN"),
		TLSCertPath:os.Getenv("FORGEOS_SIGNING_TLS_CERT"),
		TLSKeyPath:os.Getenv("FORGEOS_SIGNING_TLS_KEY"),
		ClientCAPath:os.Getenv("FORGEOS_SIGNING_CLIENT_CA"),
		BearerToken:os.Getenv("FORGEOS_SIGNING_BEARER_TOKEN"),
		JavaPath:os.Getenv("FORGEOS_SIGNING_JAVA"),
		JarSignerPath:os.Getenv("FORGEOS_SIGNING_JARSIGNER"),
		SignAPKJar:os.Getenv("FORGEOS_SIGNING_SIGNAPK_JAR"),
		CertificatePath:os.Getenv("FORGEOS_SIGNING_CERT"),
		PrivateKeyPath:os.Getenv("FORGEOS_SIGNING_PRIVATE_KEY"),
		WorkDir:os.Getenv("FORGEOS_SIGNING_WORKDIR"),
		MaxArtifactBytes:20*1024*1024*1024,
		SignTimeout:time.Hour,
	}
	if c.Listen==""{c.Listen="127.0.0.1:9444"}
	if c.JavaPath==""{c.JavaPath="/usr/bin/java"}
	if c.JarSignerPath==""{c.JarSignerPath="/usr/bin/jarsigner"}
	if value:=os.Getenv("FORGEOS_SIGNING_MAX_BYTES");value!=""{n,err:=strconv.ParseInt(value,10,64);if err!=nil{return c,err};c.MaxArtifactBytes=n}
	if value:=os.Getenv("FORGEOS_SIGNING_TIMEOUT_SECONDS");value!=""{n,err:=strconv.Atoi(value);if err!=nil{return c,err};c.SignTimeout=time.Duration(n)*time.Second}
	if err:=c.Validate();err!=nil{return c,err}
	return c,nil
}

func (c Config) Validate()error{
	host,port,err:=net.SplitHostPort(c.Listen);if err!=nil{return fmt.Errorf("signing listen address must be host:port: %w",err)}
	ip:=net.ParseIP(host);if ip==nil||ip.IsUnspecified(){return errors.New("signing service must bind to an explicit private interface address")}
	if p,err:=strconv.Atoi(port);err!=nil||p<1||p>65535{return errors.New("signing service port is invalid")}
	for name,value:=range map[string]string{"TLS certificate":c.TLSCertPath,"TLS private key":c.TLSKeyPath,"client CA":c.ClientCAPath,"signapk JAR":c.SignAPKJar,"release certificate":c.CertificatePath,"release private key":c.PrivateKeyPath,"work directory":c.WorkDir,"Java executable":c.JavaPath,"jarsigner executable":c.JarSignerPath}{
		if value==""||!filepath.IsAbs(value){return fmt.Errorf("%s path must be absolute",name)}
	}
	if len(c.BearerToken)<32{return errors.New("signing service bearer token must contain at least 32 characters")}
	if c.MaxArtifactBytes<1024||c.MaxArtifactBytes>20*1024*1024*1024{return errors.New("signing artifact size limit must be between 1 KiB and 20 GiB")}
	if c.SignTimeout<time.Minute||c.SignTimeout>24*time.Hour{return errors.New("signing timeout must be between one minute and 24 hours")}
	for _,p:=range []string{c.TLSCertPath,c.TLSKeyPath,c.ClientCAPath,c.SignAPKJar,c.CertificatePath,c.PrivateKeyPath,c.JavaPath,c.JarSignerPath}{if strings.Contains(p,"\x00"){return errors.New("signing path contains a NUL byte")}}
	return nil
}

func validateRootOwnedReadOnly(path string,allowGroupRead bool)error{
	st,err:=os.Lstat(path);if err!=nil{return err}
	if !st.Mode().IsRegular()||st.Mode()&os.ModeSymlink!=0{return fmt.Errorf("%s must be a regular non-symlink file",path)}
	sys,ok:=st.Sys().(*syscallStat);_ = sys;_ = ok
	return nil
}
