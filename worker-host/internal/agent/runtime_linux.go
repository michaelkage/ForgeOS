//go:build linux

package agent

import (
	"bytes"
	"bufio"
	"crypto/rand"
	"crypto/ed25519"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"net/netip"
	"os/user"
	"regexp"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type LinuxConfig struct {
	StateDir string `json:"stateDir"`
	ChrootBase string `json:"chrootBase"`
	CgroupParent string `json:"cgroupParent"`
	JailerPath string `json:"jailerPath"`
	FirecrackerPath string `json:"firecrackerPath"`
	KernelPaths map[string]string `json:"kernelPaths"`
	ImagePaths map[string]string `json:"imagePaths"`
	EgressPolicies map[string][]string `json:"egressPolicies"`
	DNSResolvers []string `json:"dnsResolvers"`
	VMMUIDBase int `json:"vmmUidBase"`
	VMMGIDBase int `json:"vmmGidBase"`
	IOBytesPerSecond int64 `json:"ioBytesPerSecond"`
	VsockPort uint32 `json:"vsockPort"`
	BootstrapAPIBaseURL string `json:"bootstrapApiBaseUrl"`
	SigningKey ed25519.PrivateKey `json:"-"`
}

type LinuxRuntime struct {
	cfg LinuxConfig
	mu sync.Mutex
	evidence map[string]IsolationProfile
}

type runtimeMeta struct {
	Resources Resources `json:"resources"`
	EgressPolicyID string `json:"egressPolicyId"`
	ID string `json:"id"`
	CreatedAt time.Time `json:"createdAt"`
	Deadline time.Time `json:"deadline"`
	UID int `json:"uid"`
	GID int `json:"gid"`
	Tap string `json:"tap"`
	GuestIP string `json:"guestIp"`
	GatewayIP string `json:"gatewayIp"`
	NetworkCIDR string `json:"networkCidr"`
	NetNS string `json:"netns"`
	HostVeth string `json:"hostVeth"`
	GuestVeth string `json:"guestVeth"`
	HostVethIP string `json:"hostVethIp"`
	GuestVethIP string `json:"guestVethIp"`
	Mapper string `json:"mapper"`
	PolicyTable string `json:"policyTable"`
	NATTable string `json:"natTable"`
	CgroupPath string `json:"cgroupPath"`
	JailDir string `json:"jailDir"`
	RootDir string `json:"rootDir"`
	DiskPath string `json:"diskPath"`
	Mounted bool `json:"mounted"`
	Opened bool `json:"opened"`
}

func NewLinuxRuntime(cfg LinuxConfig) (*LinuxRuntime,error) {
	if cfg.StateDir==""||cfg.ChrootBase==""||cfg.CgroupParent==""||cfg.JailerPath==""||cfg.FirecrackerPath=="" { return nil,errors.New("Linux runtime paths are required") }
	if !filepath.IsAbs(cfg.StateDir)||!filepath.IsAbs(cfg.ChrootBase) { return nil,errors.New("runtime directories must be absolute") }
	if !regexp.MustCompile(`^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*//go:build linux

package agent

import (
	"bytes"
	"crypto/rand"
	"crypto/ed25519"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"net/netip"
	"os/user"
	"regexp"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type LinuxConfig struct {
	StateDir string `json:"stateDir"`
	ChrootBase string `json:"chrootBase"`
	CgroupParent string `json:"cgroupParent"`
	JailerPath string `json:"jailerPath"`
	FirecrackerPath string `json:"firecrackerPath"`
	KernelPaths map[string]string `json:"kernelPaths"`
	ImagePaths map[string]string `json:"imagePaths"`
	EgressPolicies map[string][]string `json:"egressPolicies"`
	DNSResolvers []string `json:"dnsResolvers"`
	VMMUIDBase int `json:"vmmUidBase"`
	VMMGIDBase int `json:"vmmGidBase"`
	IOBytesPerSecond int64 `json:"ioBytesPerSecond"`
	VsockPort uint32 `json:"vsockPort"`
	BootstrapAPIBaseURL string `json:"bootstrapApiBaseUrl"`
	SigningKey ed25519.PrivateKey `json:"-"`
}

type LinuxRuntime struct {
	cfg LinuxConfig
	mu sync.Mutex
	evidence map[string]IsolationProfile
}

type runtimeMeta struct {
	Resources Resources `json:"resources"`
	EgressPolicyID string `json:"egressPolicyId"`
	ID string `json:"id"`
	CreatedAt time.Time `json:"createdAt"`
	Deadline time.Time `json:"deadline"`
	UID int `json:"uid"`
	GID int `json:"gid"`
	Tap string `json:"tap"`
	GuestIP string `json:"guestIp"`
	GatewayIP string `json:"gatewayIp"`
	NetworkCIDR string `json:"networkCidr"`
	NetNS string `json:"netns"`
	HostVeth string `json:"hostVeth"`
	GuestVeth string `json:"guestVeth"`
	HostVethIP string `json:"hostVethIp"`
	GuestVethIP string `json:"guestVethIp"`
	Mapper string `json:"mapper"`
	PolicyTable string `json:"policyTable"`
	NATTable string `json:"natTable"`
	CgroupPath string `json:"cgroupPath"`
	JailDir string `json:"jailDir"`
	RootDir string `json:"rootDir"`
	DiskPath string `json:"diskPath"`
	Mounted bool `json:"mounted"`
	Opened bool `json:"opened"`
}

func NewLinuxRuntime(cfg LinuxConfig) (*LinuxRuntime,error) {
	if cfg.StateDir==""||cfg.ChrootBase==""||cfg.CgroupParent==""||cfg.JailerPath==""||cfg.FirecrackerPath=="" { return nil,errors.New("Linux runtime paths are required") }
	).MatchString(cfg.CgroupParent)||strings.Contains(cfg.CgroupParent,".."){return nil,errors.New("cgroup parent must be a safe relative path")}
	if cfg.VMMUIDBase+2000>60000||cfg.VMMGIDBase+2000>60000{return nil,errors.New("VMM identity pool exceeds the reserved system range")}
	if cfg.VMMUIDBase<10000||cfg.VMMGIDBase<10000||cfg.IOBytesPerSecond<1_048_576 { return nil,errors.New("VMM identities and disk I/O limit are unsafe") }
	if cfg.VsockPort==0 { cfg.VsockPort=4050 }
	if cfg.BootstrapAPIBaseURL=="" { return nil,errors.New("bootstrap API base URL is required") }; apiURL,apiErr:=url.Parse(cfg.BootstrapAPIBaseURL); if apiErr!=nil||apiURL.Scheme!="https:"||apiURL.Host==""||apiURL.User!=nil||apiURL.RawQuery!=""||apiURL.Fragment!="" { return nil,errors.New("bootstrap API base URL must be a credential-free HTTPS origin") }; if len(cfg.SigningKey)!=ed25519.PrivateKeySize{return nil,errors.New("Ed25519 signing key is required")}
	for arch,path:=range cfg.KernelPaths { if (arch!="x86_64"&&arch!="arm64")||!filepath.IsAbs(path){return nil,errors.New("invalid kernel path mapping")} }
	for digest,path:=range cfg.ImagePaths { if !digestPattern.MatchString(digest)||!filepath.IsAbs(path){return nil,errors.New("invalid image digest mapping")} }
	for id,cidrs:=range cfg.EgressPolicies {
		if !workerPattern.MatchString(id)||len(cidrs)==0 {return nil,errors.New("egress policies must have a stable ID and non-empty CIDR allowlist")}
		for _,raw:=range cidrs { p,e:=netip.ParsePrefix(raw);if e!=nil||!p.Addr().Is4()||isForbiddenEgress(p){return nil,fmt.Errorf("egress policy %s contains an invalid, non-IPv4, or private destination",id)} }
	}
	for _,raw:=range cfg.DNSResolvers { a,e:=netip.ParseAddr(raw);if e!=nil||!a.Is4()||!a.IsGlobalUnicast()||a.IsPrivate()||a.IsLinkLocalUnicast()||isForbiddenEgress(netip.PrefixFrom(a,32)){return nil,errors.New("DNS resolver must be a public unicast IPv4 address")} }
	if len(cfg.DNSResolvers)==0{return nil,errors.New("at least one explicitly allowlisted public DNS resolver is required")}
	if err:=os.MkdirAll(cfg.StateDir,0700);err!=nil{return nil,err};if err:=os.MkdirAll(cfg.ChrootBase,0700);err!=nil{return nil,err}
	for _,p:=range []string{cfg.StateDir,cfg.ChrootBase}{st,e:=os.Lstat(p);if e!=nil{return nil,e};sys,ok:=st.Sys().(*syscall.Stat_t);if !ok||sys.Uid!=0||st.Mode().Perm()&0022!=0{return nil,fmt.Errorf("runtime directory %s must be root-owned and not group/world writable",p)}}
	return &LinuxRuntime{cfg:cfg,evidence:map[string]IsolationProfile{}},nil
}

func isForbiddenEgress(p netip.Prefix) bool {
	blocked:=[]netip.Prefix{}
	for _,s:=range []string{"0.0.0.0/8","10.0.0.0/8","100.64.0.0/10","127.0.0.0/8","169.254.0.0/16","172.16.0.0/12","192.0.0.0/24","192.0.2.0/24","192.168.0.0/16","198.18.0.0/15","198.51.100.0/24","203.0.113.0/24","224.0.0.0/4","240.0.0.0/4","::/128","::1/128","fc00::/7","fe80::/10","ff00::/8"} { blocked=append(blocked,netip.MustParsePrefix(s)) }
	for _,b:=range blocked { if p.Addr().Is4()==b.Addr().Is4()&&(p.Contains(b.Addr())||b.Contains(p.Addr())) { return true } }
	return false
}

func (r *LinuxRuntime) Provision(req ProvisionRequest,id string) error {
	r.mu.Lock();defer r.mu.Unlock()
	if !instancePattern.MatchString(id){return errors.New("invalid instance ID")}
	if err:=r.preflight();err!=nil{return err}
	if err:=regularRootOwned(r.cfg.JailerPath);err!=nil{return fmt.Errorf("jailer binary rejected: %w",err)}
	if err:=regularRootOwned(r.cfg.FirecrackerPath);err!=nil{return fmt.Errorf("Firecracker binary rejected: %w",err)}
	kernel:=r.cfg.KernelPaths[req.Architecture];baseImage:=r.cfg.ImagePaths[req.ImageDigest];cidrs,ok:=r.cfg.EgressPolicies[req.EgressPolicyID]
	if kernel==""||baseImage==""||!ok{return errors.New("architecture, immutable image digest, or egress policy is not allowlisted")}
	if err:=verifyImageDigest(baseImage,req.ImageDigest);err!=nil{return err}
	if err:=regularRootOwned(kernel);err!=nil{return fmt.Errorf("kernel image rejected: %w",err)}
	if err:=regularRootOwned(baseImage);err!=nil{return fmt.Errorf("root filesystem image rejected: %w",err)}
	meta,err:=r.makeMeta(req,id);if err!=nil{return err}
	rollback:=func(cause error)error{_ = r.cleanup(meta);return cause}
	meta.Resources=req.Resources;meta.EgressPolicyID=req.EgressPolicyID
	if err:=os.MkdirAll(filepath.Join(r.cfg.StateDir,id),0700);err!=nil{return err}
	if err:=r.writeMeta(meta);err!=nil{return err}
	if err:=r.createEncryptedDisk(meta,req.Resources.DiskGiB,baseImage);err!=nil{return rollback(err)}
	if err:=r.createCgroup(meta,req.Resources);err!=nil{return rollback(err)}
	if err:=r.setupNetwork(meta,cidrs);err!=nil{return rollback(err)}
	if err:=r.launchFirecracker(meta,req,kernel);err!=nil{return rollback(err)}
	if err:=r.sendBootstrap(meta,req);err!=nil{return rollback(err)}
	if err:=r.writeMeta(meta);err!=nil{return rollback(err)}
	profile:=IsolationProfile{
		FirecrackerMicroVM:true,DedicatedKernel:true,Jailer:true,NonRootVMM:true,NoHostMounts:true,
		NoContainerSocket:true,NoHostPIDNamespace:true,EncryptedEphemeralDisk:true,HardCPULimit:true,
		HardMemoryLimit:true,HardDiskLimit:true,HardProcessLimit:true,WallTimeLimit:true,EgressFiltering:true,
		MetadataBlocked:true,DestroyAfterJob:true,EgressPolicyID:req.EgressPolicyID,Resources:req.Resources,
	}
	r.evidence[id]=profile
	return nil
}

func (r *LinuxRuntime) Evidence(id string)(IsolationProfile,error){
	r.mu.Lock();defer r.mu.Unlock()
	m,err:=r.readMeta(id);if err!=nil{return IsolationProfile{},errors.New("isolation evidence is unavailable")};if p,ok:=r.evidence[id];ok{return p,nil};return IsolationProfile{FirecrackerMicroVM:true,DedicatedKernel:true,Jailer:true,NonRootVMM:true,NoHostMounts:true,NoContainerSocket:true,NoHostPIDNamespace:true,EncryptedEphemeralDisk:true,HardCPULimit:true,HardMemoryLimit:true,HardDiskLimit:true,HardProcessLimit:true,WallTimeLimit:true,EgressFiltering:true,MetadataBlocked:true,DestroyAfterJob:true,EgressPolicyID:m.EgressPolicyID,Resources:m.Resources},nil
}

func (r *LinuxRuntime) Inspect(id string)(string,error){
	r.mu.Lock();defer r.mu.Unlock()
	meta,err:=r.readMeta(id);if err!=nil { if os.IsNotExist(err){return "stopped",nil};return "unknown",err }
	if time.Now().After(meta.Deadline){if err:=r.cleanup(meta);err!=nil{return "unknown",err};return "stopped",nil}
	procs,err:=os.ReadFile(filepath.Join(meta.CgroupPath,"cgroup.procs"));if err!=nil{return "unknown",err}
	if len(bytes.TrimSpace(procs))==0{if err:=r.cleanup(meta);err!=nil{return "unknown",err};return "stopped",nil}
	state,err:=r.firecrackerState(meta);if err!=nil{return "unknown",nil}
	if state=="Running"{return "running",nil}
	if err:=r.cleanup(meta);err!=nil{return "unknown",err};return "stopped",nil
}

func (r *LinuxRuntime) Terminate(id string)error{
	r.mu.Lock();defer r.mu.Unlock()
	meta,err:=r.readMeta(id);if err!=nil {if os.IsNotExist(err){return nil};return err}
	if err:=r.cleanup(meta);err!=nil{return err}
	delete(r.evidence,id)
	return nil
}

func (r *LinuxRuntime) preflight()error{
	if os.Geteuid()!=0{return errors.New("host agent must run as root")}
	if _,err:=os.Stat("/dev/kvm");err!=nil{return errors.New("KVM device is unavailable")}
	for _,p:=range []string{r.cfg.StateDir,r.cfg.ChrootBase}{if err:=os.MkdirAll(p,0700);err!=nil{return err};st,e:=os.Lstat(p);if e!=nil{return e};sys,ok:=st.Sys().(*syscall.Stat_t);if !ok||sys.Uid!=0||st.Mode().Perm()&0022!=0{return fmt.Errorf("runtime directory %s must be root-owned and not group/world writable",p)}}
	var fs syscall.Statfs_t
	if err:=syscall.Statfs("/sys/fs/cgroup",&fs);err!=nil{return err}
	if uint64(fs.Type)!=0x63677270{return errors.New("cgroup v2 is required")}
	controllers,err:=os.ReadFile(filepath.Join("/sys/fs/cgroup",r.cfg.CgroupParent,"cgroup.controllers"));if err!=nil{return fmt.Errorf("cgroup parent is not delegated: %w",err)}
	for _,c:=range []string{"cpu","memory","pids","io"}{if !strings.Contains(" "+string(controllers)+" "," "+c+" "){return fmt.Errorf("cgroup v2 controller %s is unavailable",c)}}
	for _,p:=range []string{r.cfg.JailerPath,r.cfg.FirecrackerPath,"/usr/sbin/cryptsetup","/usr/sbin/mkfs.ext4","/usr/bin/mount","/usr/bin/umount","/usr/sbin/ip","/usr/sbin/nft","/usr/bin/setfacl"}{if _,err:=os.Stat(p);err!=nil{return fmt.Errorf("required host executable %s unavailable",p)}}
	return nil
}

func regularRootOwned(path string)error{
	st,err:=os.Lstat(path);if err!=nil{return err};if !st.Mode().IsRegular()||st.Mode()&os.ModeSymlink!=0{return errors.New("must be a regular non-symlink file")}
	if sys,ok:=st.Sys().(*syscall.Stat_t);!ok||sys.Uid!=0{return errors.New("must be owned by root")}
	if st.Mode().Perm()&0022!=0{return errors.New("must not be group/world writable")}
	return nil
}

func (r *LinuxRuntime) makeMeta(req ProvisionRequest,id string)(runtimeMeta,error){
	sum:=sha256.Sum256([]byte(id))
	usedUID:=map[int]bool{};usedNet:=map[string]bool{}
	entries,_:=os.ReadDir(r.cfg.StateDir)
	for _,entry:=range entries{if !entry.IsDir(){continue};b,e:=os.ReadFile(filepath.Join(r.cfg.StateDir,entry.Name(),"runtime.json"));if e!=nil{continue};var old runtimeMeta;if json.Unmarshal(b,&old)==nil{usedUID[old.UID]=true;usedNet[old.NetworkCIDR]=true}}
	slot:=int(sum[0])<<8|int(sum[1]);slot%=2000;uid,gid:=0,0
	for n:=0;n<2000;n++{candidate:=(slot+n)%2000;u:=r.cfg.VMMUIDBase+candidate;if !usedUID[u]{uid=u;gid=r.cfg.VMMGIDBase+candidate;break}}
	if uid==0||gid==0{return runtimeMeta{},errors.New("no free per-VM VMM identity remains")}
	netSlot:=int(sum[2])<<8|int(sum[3]);netSlot%=16000
	var gateway,guest,hostVethIP,guestVethIP netip.Addr
	var network netip.Prefix
	found:=false
	for n:=0;n<16000;n++{idx:=(netSlot+n)%16000;base:=uint32(0x0afd0000)+uint32(idx*4);g:=netip.AddrFrom4([4]byte{byte(base>>24),byte(base>>16),byte(base>>8),byte(base)});p:=netip.PrefixFrom(g,30).Masked();if usedNet[p.String()]{continue};gateway=g;guest=g.Next();network=p
		vbase:=uint32(0x0afc0000)+uint32(idx*4);hostVethIP=netip.AddrFrom4([4]byte{byte(vbase>>24),byte(vbase>>16),byte(vbase>>8),byte(vbase)});guestVethIP=hostVethIP.Next();found=true;break}
	if !found{return runtimeMeta{},errors.New("no free per-VM network range remains")}
	short:=hex.EncodeToString(sum[:6]);jailDir:=filepath.Join(r.cfg.ChrootBase,"firecracker",id)
	return runtimeMeta{ID:id,CreatedAt:time.Now().UTC(),Deadline:time.Now().Add(time.Duration(req.Resources.WallTimeSeconds)*time.Second).UTC(),UID:uid,GID:gid,Tap:"ft"+short[:11],GuestIP:guest.String(),GatewayIP:gateway.String(),NetworkCIDR:network.String(),NetNS:"fn"+short[:11],HostVeth:"fh"+short[:11],GuestVeth:"fv"+short[:11],HostVethIP:hostVethIP.String(),GuestVethIP:guestVethIP.String(),Mapper:"fg"+short,PolicyTable:"forgeos_"+short,NATTable:"forgeos_nat_"+short,CgroupPath:filepath.Join("/sys/fs/cgroup",r.cfg.CgroupParent,id),JailDir:jailDir,RootDir:filepath.Join(jailDir,"root"),DiskPath:filepath.Join(r.cfg.StateDir,id,"ephemeral.luks"),Resources:req.Resources,EgressPolicyID:req.EgressPolicyID},nil
}

func (r *LinuxRuntime) createCgroup(m runtimeMeta,res Resources)error{
	parent:=filepath.Join("/sys/fs/cgroup",r.cfg.CgroupParent)
	if err:=os.MkdirAll(parent,0750);err!=nil{return err}
	if err:=os.WriteFile(filepath.Join(parent,"cgroup.subtree_control"),[]byte("+cpu +memory +pids +io"),0640);err!=nil{return fmt.Errorf("enable cgroup v2 controllers: %w",err)}
	if err:=os.Mkdir(m.CgroupPath,0750);err!=nil{return err}
	quota:=res.CPUCores*100000
	values:=map[string]string{"memory.max":strconv.FormatInt(int64(res.MemoryMiB)*1024*1024,10),"memory.swap.max":"0","pids.max":strconv.Itoa(res.ProcessLimit),"cpu.max":fmt.Sprintf("%d 100000",quota)}
	st,e:=os.Stat(m.DiskPath);if e!=nil{return e};sys,ok:=st.Sys().(*syscall.Stat_t);if !ok{return errors.New("cannot determine ephemeral disk backing device")}
	dev:=uint64(sys.Dev);major:=(dev>>8)&0xfff | (dev>>32)&0xfffff000;minor:=dev&0xff | (dev>>12)&0xffffff00
	values["io.max"]=fmt.Sprintf("%d:%d rbps=%d wbps=%d riops=1000 wiops=1000",major,minor,r.cfg.IOBytesPerSecond,r.cfg.IOBytesPerSecond)
	for name,value:=range values{if err:=os.WriteFile(filepath.Join(m.CgroupPath,name),[]byte(value),0640);err!=nil{return fmt.Errorf("apply cgroup %s: %w",name,err)}}
	return nil
}

func (r *LinuxRuntime) createEncryptedDisk(m runtimeMeta,diskGiB int,baseImage string)error{
	f,err:=os.OpenFile(m.DiskPath,os.O_CREATE|os.O_EXCL|os.O_RDWR,0600);if err!=nil{return err}
	if err=f.Truncate(int64(diskGiB)*1024*1024*1024);err!=nil{_ = f.Close();return err};_ = f.Close()
	key:=make([]byte,64);if _,err:=rand.Read(key);err!=nil{return err};defer func(){for i:=range key{key[i]=0}}()
	if err:=runInput(context.Background(),"/usr/sbin/cryptsetup",key,"luksFormat","--batch-mode","--type","luks2","--key-file","-",m.DiskPath);err!=nil{return fmt.Errorf("encrypt ephemeral disk: %w",err)}
	if err:=runInput(context.Background(),"/usr/sbin/cryptsetup",key,"open","--key-file","-",m.DiskPath,m.Mapper);err!=nil{return err}
	m.Opened=true
	device:=filepath.Join("/dev/mapper",m.Mapper)
	if err:=run(context.Background(),"/usr/sbin/mkfs.ext4","-F","-m","0",device);err!=nil{return err}
	if err:=os.MkdirAll(m.JailDir,0700);err!=nil{return err}
	if err:=run(context.Background(),"/usr/bin/mount",device,m.JailDir);err!=nil{return err}
	m.Mounted=true
	root:=filepath.Join(m.JailDir,"root")
	for _,p:=range []string{filepath.Join(root,"boot"),filepath.Join(root,"run"),filepath.Join(root,"var/lib/forgeos")}{if err:=os.MkdirAll(p,0750);err!=nil{return err}}
	target:=filepath.Join(root,"var/lib/forgeos/rootfs.ext4")
	src,err:=os.Open(baseImage);if err!=nil{return err};defer src.Close()
	dst,err:=os.OpenFile(target,os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600);if err!=nil{return err}
	written,copyErr:=io.Copy(dst,src);closeErr:=dst.Close();if copyErr!=nil{return copyErr};if closeErr!=nil{return closeErr};if written>=int64(diskGiB)*1024*1024*1024{return errors.New("immutable root filesystem does not fit encrypted ephemeral disk")}
	if err:=os.Chown(target,m.UID,m.GID);err!=nil{return err}
	return nil
}

func (r *LinuxRuntime) setupNetwork(m runtimeMeta,cidrs []string)error{
	if err:=run(context.Background(),"/usr/sbin/ip","netns","add",m.NetNS);err!=nil{return err}
	if err:=run(context.Background(),"/usr/sbin/ip","link","add",m.HostVeth,"type","veth","peer","name",m.GuestVeth);err!=nil{return err}
	if err:=run(context.Background(),"/usr/sbin/ip","link","set",m.GuestVeth,"netns",m.NetNS);err!=nil{return err}
	if err:=run(context.Background(),"/usr/sbin/ip","addr","add",m.HostVethIP+"/30","dev",m.HostVeth);err!=nil{return err}
	if err:=run(context.Background(),"/usr/sbin/ip","link","set",m.HostVeth,"up");err!=nil{return err}
	ns:=func(args ...string)error{return run(context.Background(),"/usr/sbin/ip",append([]string{"netns","exec",m.NetNS,"ip"},args...)...)}
	if err:=ns("link","set","lo","up");err!=nil{return err}
	if err:=ns("addr","add",m.GuestVethIP+"/30","dev",m.GuestVeth);err!=nil{return err}
	if err:=ns("link","set",m.GuestVeth,"up");err!=nil{return err}
	if err:=ns("route","add","default","via",m.HostVethIP);err!=nil{return err}
	if err:=run(context.Background(),"/usr/sbin/ip","netns","exec",m.NetNS,"sysctl","-w","net.ipv4.ip_forward=1");err!=nil{return err}
	if err:=run(context.Background(),"/usr/sbin/ip","netns","exec",m.NetNS,"ip","tuntap","add","dev",m.Tap,"mode","tap","user",strconv.Itoa(m.UID));err!=nil{return err}
	if err:=ns("addr","add",m.GatewayIP+"/30","dev",m.Tap);err!=nil{return err}
	if err:=ns("link","set",m.Tap,"up");err!=nil{return err}
	if err:=os.WriteFile("/proc/sys/net/ipv4/ip_forward",[]byte("1"),0644);err!=nil{return err}
	allow:=make([]string,0,len(cidrs));for _,raw:=range cidrs{p,e:=netip.ParsePrefix(raw);if e!=nil||isForbiddenEgress(p){return errors.New("egress CIDR failed validation")};allow=append(allow,raw)}
	var host strings.Builder
	host.WriteString("table inet "+m.PolicyTable+" { chain input { type filter hook input priority -300; policy accept; iifname \""+m.HostVeth+"\" drop; } chain forward { type filter hook forward priority -300; policy accept; iifname \""+m.HostVeth+"\" ct state established,related accept; ")
	for _,cidr:=range allow{host.WriteString("iifname \""+m.HostVeth+"\" ip daddr "+cidr+" tcp dport 443 accept; ")}
	for _,ip:=range r.cfg.DNSResolvers{host.WriteString("iifname \""+m.HostVeth+"\" ip daddr "+ip+" udp dport 53 accept; iifname \""+m.HostVeth+"\" ip daddr "+ip+" tcp dport 53 accept; ")}
	host.WriteString("iifname \""+m.HostVeth+"\" drop; oifname \""+m.HostVeth+"\" ct state established,related accept; } }\n")
	host.WriteString("table ip "+m.NATTable+" { chain postrouting { type nat hook postrouting priority srcnat; policy accept; ip saddr "+m.NetworkCIDR+" masquerade; } }\n")
	if err:=runInput(context.Background(),"/usr/sbin/nft",[]byte(host.String()),"-f","-");err!=nil{return err}
	var inside strings.Builder
	inside.WriteString("table inet forgeos_guest { chain input { type filter hook input priority -300; policy accept; iifname \""+m.Tap+"\" drop; } chain forward { type filter hook forward priority -300; policy drop; iifname \""+m.Tap+"\" ct state established,related accept; ")
	for _,cidr:=range allow{inside.WriteString("iifname \""+m.Tap+"\" oifname \""+m.GuestVeth+"\" ip daddr "+cidr+" tcp dport 443 accept; ")}
	for _,ip:=range r.cfg.DNSResolvers{inside.WriteString("iifname \""+m.Tap+"\" oifname \""+m.GuestVeth+"\" ip daddr "+ip+" udp dport 53 accept; iifname \""+m.Tap+"\" oifname \""+m.GuestVeth+"\" ip daddr "+ip+" tcp dport 53 accept; ")}
	inside.WriteString("iifname \""+m.Tap+"\" drop; oifname \""+m.Tap+"\" ct state established,related accept; } }\n")
	return runInput(context.Background(),"/usr/sbin/ip",[]byte(inside.String()),"netns","exec",m.NetNS,"nft","-f","-")
}

func (r *LinuxRuntime) launchFirecracker(m runtimeMeta,req ProvisionRequest,kernel string)error{
	kernelTarget:=filepath.Join(m.RootDir,"boot/vmlinux")
	src,err:=os.Open(kernel);if err!=nil{return err};defer src.Close()
	dst,err:=os.OpenFile(kernelTarget,os.O_CREATE|os.O_EXCL|os.O_WRONLY,0500);if err!=nil{return err}
	_,e:=io.Copy(dst,src);ce:=dst.Close();if e!=nil{return e};if ce!=nil{return ce}
	if err:=os.Chown(kernelTarget,m.UID,m.GID);err!=nil{return err}
	if err:=run(context.Background(),"/usr/bin/setfacl","-m","u:"+strconv.Itoa(m.UID)+":rw","/dev/kvm");err!=nil{return err}
	apiSocket:=filepath.Join(m.RootDir,"run/firecracker.socket")
	vsockSocket:=filepath.Join(m.RootDir,"run/forgeos-vsock.sock")
	args:=[]string{"--id",m.ID,"--exec-file",r.cfg.FirecrackerPath,"--uid",strconv.Itoa(m.UID),"--gid",strconv.Itoa(m.GID),"--chroot-base-dir",r.cfg.ChrootBase,"--cgroup-version","2","--parent-cgroup",filepath.Join(r.cfg.CgroupParent,m.ID),"--netns","/run/netns/"+m.NetNS,"--resource-limit","no-file=4096","--new-pid-ns","--seccomp-level","2","--","--api-sock","/run/firecracker.socket"}
	cmd:=exec.Command(r.cfg.JailerPath,args...)
	cmd.Stdout=io.Discard;cmd.Stderr=io.Discard
	if err:=cmd.Start();err!=nil{return fmt.Errorf("start Firecracker jailer: %w",err)}
	if err:=waitForSocket(apiSocket,10*time.Second);err!=nil{_ = cmd.Process.Kill();return err}
	api:=newUnixAPI(apiSocket)
	machine:=map[string]any{"vcpu_count":req.Resources.CPUCores,"mem_size_mib":req.Resources.MemoryMiB,"smt":false}
	boot:=map[string]any{"kernel_image_path":"/boot/vmlinux","boot_args":fmt.Sprintf("console=ttyS0 reboot=k panic=1 ip=%s::%s:255.255.255.252::eth0:off",m.GuestIP,m.GatewayIP)}
	drive:=map[string]any{"drive_id":"rootfs","path_on_host":"/var/lib/forgeos/rootfs.ext4","is_root_device":true,"is_read_only":false}
	network:=map[string]any{"iface_id":"eth0","guest_mac":guestMAC(m.ID),"host_dev_name":m.Tap}
	vsock:=map[string]any{"guest_cid":3,"uds_path":"/run/forgeos-vsock.sock"}
	for path,value:=range map[string]any{"/machine-config":machine,"/boot-source":boot,"/drives/rootfs":drive,"/network-interfaces/eth0":network,"/vsock":vsock}{if err:=api.Put(path,value);err!=nil{_ = cmd.Process.Kill();return fmt.Errorf("configure Firecracker %s: %w",path,err)}}
	if err:=api.Put("/actions",map[string]any{"action_type":"InstanceStart"});err!=nil{_ = cmd.Process.Kill();return err}
	return nil
}

func (r *LinuxRuntime) sendBootstrap(m runtimeMeta,req ProvisionRequest)error{
	nonce,nonceErr:=randomUUID();if nonceErr!=nil{return nonceErr};issued:=time.Now().UTC();payload:=map[string]any{"schemaVersion":1,"jobId":req.JobID,"attempt":req.Attempt,"architecture":req.Architecture,"imageDigest":req.ImageDigest,"apiBaseUrl":r.cfg.BootstrapAPIBaseURL,"bootstrapCredential":req.BootstrapCredential,"nonce":nonce,"issuedAt":issued,"expiresAt":issued.Add(90*time.Second)}
	// The guest verifies the Ed25519 signature using the pinned host key embedded in its immutable image.
	signer,ok:=r.(interface{SignBootstrap(any)(string,error)});if !ok{return errors.New("host runtime bootstrap signer is unavailable")}
	sig,err:=signer.SignBootstrap(payload);if err!=nil{return err}
	envelope:=map[string]any{"payload":payload,"signature":sig}
	data,err:=json.Marshal(envelope);if err!=nil{return err}
	if len(data)>64*1024{return errors.New("bootstrap envelope too large")}
	deadline:=time.Now().Add(60*time.Second)
	for time.Now().Before(deadline){
		conn,err:=net.DialTimeout("unix",filepath.Join(m.RootDir,"run/forgeos-vsock.sock"),2*time.Second)
		if err==nil{
			_ = conn.SetDeadline(time.Now().Add(5*time.Second))
			if _,err=fmt.Fprintf(conn,"CONNECT %d\n",r.cfg.VsockPort);err==nil{
				line,readErr:=bufio.NewReader(conn).ReadString('\n')
				if readErr!=nil||!strings.HasPrefix(line,"OK"){_ = conn.Close();time.Sleep(250*time.Millisecond);continue}
				var hdr [4]byte;hdr[0]=byte(len(data)>>24);hdr[1]=byte(len(data)>>16);hdr[2]=byte(len(data)>>8);hdr[3]=byte(len(data))
				_,err=io.Copy(conn,bytes.NewReader(append(hdr[:],data...)))
			}
			_ = conn.Close()
			if err==nil{_ = conn.SetReadDeadline(time.Now().Add(5*time.Second));ack,ackErr:=bufio.NewReader(conn).ReadString('\n');if ackErr==nil&&ack=="BOOTSTRAP_REDEEMED\n"{return nil};err=errors.New("guest did not confirm bootstrap redemption")}
		}
		time.Sleep(250*time.Millisecond)
	}
	return errors.New("guest vsock bootstrap endpoint did not become ready")
}

func (r *LinuxRuntime) SignBootstrap(value any)(string,error){return signCanonical(r.cfg.SigningKey,value)}

func (r *LinuxRuntime) firecrackerState(m runtimeMeta)(string,error){
	var out struct{State string `json:"state"`}
	err:=newUnixAPI(filepath.Join(m.RootDir,"run/firecracker.socket")).Get("/",&out)
	return out.State,err
}

func (r *LinuxRuntime) cleanup(m runtimeMeta)error{
	cgroupProcs:=filepath.Join(m.CgroupPath,"cgroup.procs")
	if _,e:=os.Stat(cgroupProcs);e==nil{
		if _,e=os.Stat(filepath.Join(m.CgroupPath,"cgroup.kill"));e==nil{if e=os.WriteFile(filepath.Join(m.CgroupPath,"cgroup.kill"),[]byte("1"),0200);e!=nil{return fmt.Errorf("kill Firecracker cgroup: %w",e)}}else{
			b,_:=os.ReadFile(cgroupProcs);for _,line:=range strings.Fields(string(b)){pid,_:=strconv.Atoi(line);if pid>1{_ = syscall.Kill(pid,syscall.SIGKILL)}}
		}
		deadline:=time.Now().Add(15*time.Second)
		for time.Now().Before(deadline){b,e:=os.ReadFile(cgroupProcs);if e!=nil||len(bytes.TrimSpace(b))==0{break};time.Sleep(100*time.Millisecond)}
		b,e:=os.ReadFile(cgroupProcs);if e==nil&&len(bytes.TrimSpace(b))>0{return errors.New("Firecracker processes remain; refusing to detach their resources")}
	}
	if exists,e:=nftTableExists("inet",m.PolicyTable);e!=nil{return e}else if exists{if e=run(context.Background(),"/usr/sbin/nft","delete","table","inet",m.PolicyTable);e!=nil{return fmt.Errorf("remove VM egress filter: %w",e)}}
	if exists,e:=nftTableExists("ip",m.NATTable);e!=nil{return e}else if exists{if e=run(context.Background(),"/usr/sbin/nft","delete","table","ip",m.NATTable);e!=nil{return fmt.Errorf("remove VM NAT rules: %w",e)}}
	if exists,_:=ipLinkExists(m.HostVeth);exists{if e:=run(context.Background(),"/usr/sbin/ip","link","delete",m.HostVeth);e!=nil{return fmt.Errorf("remove VM host veth: %w",e)}}
	if mounted,_:=isMountPoint(m.JailDir);mounted{if e:=run(context.Background(),"/usr/bin/umount",m.JailDir);e!=nil{return fmt.Errorf("unmount encrypted VM storage: %w",e)}}
	if _,e:=os.Stat(filepath.Join("/dev/mapper",m.Mapper));e==nil{if e=run(context.Background(),"/usr/sbin/cryptsetup","close",m.Mapper);e!=nil{return fmt.Errorf("close encrypted VM storage: %w",e)}}
	if _,e:=os.Stat(m.CgroupPath);e==nil{if e=os.Remove(m.CgroupPath);e!=nil{return fmt.Errorf("remove VM cgroup: %w",e)}}
	_ = run(context.Background(),"/usr/bin/setfacl","-x","u:"+strconv.Itoa(m.UID),"/dev/kvm")
	if _,e:=os.Stat(filepath.Join("/run/netns",m.NetNS));e==nil{if e=run(context.Background(),"/usr/sbin/ip","netns","delete",m.NetNS);e!=nil{return fmt.Errorf("remove VM network namespace: %w",e)}}
	if mounted,_:=isMountPoint(m.JailDir);mounted{return errors.New("encrypted VM storage remains mounted after teardown")}
	if _,e:=os.Stat(filepath.Join("/dev/mapper",m.Mapper));e==nil{return errors.New("encrypted VM mapping remains after teardown")}
	if _,e:=os.Stat(m.CgroupPath);e==nil{return errors.New("VM cgroup remains after teardown")}
	if exists,_:=ipLinkExists(m.HostVeth);exists{return errors.New("VM host network interface remains after teardown")}
	if _,e:=os.Stat(filepath.Join("/run/netns",m.NetNS));e==nil{return errors.New("VM network namespace remains after teardown")}
	if _,e:=os.Stat(m.JailDir);e==nil{if e=os.RemoveAll(m.JailDir);e!=nil{return e}}
	_ = os.RemoveAll(filepath.Join(r.cfg.StateDir,m.ID))
	delete(r.evidence,m.ID)
	return nil
}
func nftTableExists(family,table string)(bool,error){cmd:=exec.Command("/usr/sbin/nft","list","table",family,table);err:=cmd.Run();if err==nil{return true,nil};if _,ok:=err.(*exec.ExitError);ok{return false,nil};return false,err}
func ipLinkExists(name string)(bool,error){cmd:=exec.Command("/usr/sbin/ip","link","show","dev",name);err:=cmd.Run();if err==nil{return true,nil};if _,ok:=err.(*exec.ExitError);ok{return false,nil};return false,err}

func isMountPoint(path string)(bool,error){b,e:=os.ReadFile("/proc/self/mountinfo");if e!=nil{return false,e};clean:=filepath.Clean(path);for _,line:=range strings.Split(string(b),"\n"){f:=strings.Fields(line);if len(f)>4&&f[4]==clean{return true,nil}};return false,nil}
func (r *LinuxRuntime) Recover()error{r.mu.Lock();defer r.mu.Unlock();entries,e:=os.ReadDir(r.cfg.StateDir);if os.IsNotExist(e){return nil};if e!=nil{return e};var errs []error;for _,entry:=range entries{if !entry.IsDir()||!instancePattern.MatchString(entry.Name()){continue};m,e:=r.readMeta(entry.Name());if e!=nil{errs=append(errs,e);continue};if e=r.cleanup(m);e!=nil{errs=append(errs,e)}};if len(errs)>0{return errors.Join(errs...)};return nil}
func (r *LinuxRuntime) SweepExpired()error{r.mu.Lock();defer r.mu.Unlock();entries,e:=os.ReadDir(r.cfg.StateDir);if e!=nil{return e};var errs []error;for _,entry:=range entries{if !entry.IsDir()||!instancePattern.MatchString(entry.Name()){continue};m,e:=r.readMeta(entry.Name());if e!=nil{errs=append(errs,e);continue};if time.Now().After(m.Deadline){if e=r.cleanup(m);e!=nil{errs=append(errs,e)}}};if len(errs)>0{return errors.Join(errs...)};return nil}
func verifyImageDigest(path,digest string)error{f,e:=os.Open(path);if e!=nil{return e};defer f.Close();h:=sha256.New();if _,e=io.Copy(h,f);e!=nil{return e};if "sha256:"+hex.EncodeToString(h.Sum(nil))!=digest{return errors.New("worker image bytes do not match the requested immutable SHA-256 digest")};return nil}
func (r *LinuxRuntime) writeMeta(m runtimeMeta)error{b,e:=json.Marshal(m);if e!=nil{return e};tmp:=filepath.Join(r.cfg.StateDir,m.ID,"runtime.json.tmp");if e=os.WriteFile(tmp,b,0600);e!=nil{return e};return os.Rename(tmp,filepath.Join(r.cfg.StateDir,m.ID,"runtime.json"))}
func (r *LinuxRuntime) readMeta(id string)(runtimeMeta,error){if !instancePattern.MatchString(id){return runtimeMeta{},errors.New("invalid instance ID")};b,e:=os.ReadFile(filepath.Join(r.cfg.StateDir,id,"runtime.json"));if e!=nil{return runtimeMeta{},e};var m runtimeMeta;e=json.Unmarshal(b,&m);return m,e}

func waitForSocket(path string,d time.Duration)error{until:=time.Now().Add(d);for time.Now().Before(until){if st,e:=os.Stat(path);e==nil&&st.Mode()&os.ModeSocket!=0{return nil};time.Sleep(50*time.Millisecond)};return errors.New("Firecracker API socket did not become ready")}
type unixAPI struct{client *http.Client}
func newUnixAPI(path string)*unixAPI{tr:=&http.Transport{DialContext:func(ctx context.Context,_,_ string)(net.Conn,error){return (&net.Dialer{Timeout:2*time.Second}).DialContext(ctx,"unix",path)}};return &unixAPI{client:&http.Client{Transport:tr,Timeout:3*time.Second}}}
func (u *unixAPI) Put(path string,v any)error{b,e:=json.Marshal(v);if e!=nil{return e};req,e:=http.NewRequest(http.MethodPut,"http://localhost"+path,bytes.NewReader(b));if e!=nil{return e};req.Header.Set("Content-Type","application/json");resp,e:=u.client.Do(req);if e!=nil{return e};defer resp.Body.Close();if resp.StatusCode<200||resp.StatusCode>=300{body,_:=io.ReadAll(io.LimitReader(resp.Body,2048));return fmt.Errorf("Firecracker API %s returned %d: %s",path,resp.StatusCode,strings.TrimSpace(string(body)))};return nil}
func (u *unixAPI) Get(path string,v any)error{resp,e:=u.client.Get("http://localhost"+path);if e!=nil{return e};defer resp.Body.Close();if resp.StatusCode!=200{return fmt.Errorf("Firecracker API returned %d",resp.StatusCode)};return json.NewDecoder(io.LimitReader(resp.Body,4096)).Decode(v)}

func run(ctx context.Context,path string,args ...string)error{cmd:=exec.CommandContext(ctx,path,args...);out,err:=cmd.CombinedOutput();if err!=nil{return fmt.Errorf("%s failed (%v): %s",filepath.Base(path),err,strings.TrimSpace(string(out)))};return nil}
func runInput(ctx context.Context,path string,input []byte,args ...string)error{cmd:=exec.CommandContext(ctx,path,args...);cmd.Stdin=bytes.NewReader(input);out,err:=cmd.CombinedOutput();if err!=nil{return fmt.Errorf("%s failed (%v): %s",filepath.Base(path),err,strings.TrimSpace(string(out)))};return nil}
func guestMAC(id string)string{h:=sha256.Sum256([]byte(id));return fmt.Sprintf("02:fc:%02x:%02x:%02x:%02x",h[0],h[1],h[2],h[3])}

