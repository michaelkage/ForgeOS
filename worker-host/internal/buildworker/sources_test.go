package buildworker

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSourceDestinationMapsVerifiedSourceKinds(t *testing.T){
	tests:=[]struct{kind,url,codename,want string}{
		{"device","https://github.com/LineageOS/android_device_google_coral","coral","device/google/coral"},
		{"kernel","https://github.com/LineageOS/android_kernel_xiaomi_sm8250","sweet","kernel/xiaomi/sm8250"},
		{"vendor","https://github.com/TheMuppets/proprietary_vendor_xiaomi","sweet","vendor/xiaomi"},
	}
	for _,tt:=range tests{got,err:=sourceDestination(pinnedSource{Kind:tt.kind,URL:tt.url},tt.codename);if err!=nil{t.Fatal(err)};if filepath.ToSlash(got)!=tt.want{t.Fatalf("%s: expected %s, got %s",tt.kind,tt.want,got)}}
}
func TestSourceDestinationRejectsMismatchedDeviceCodename(t *testing.T){
	_,err:=sourceDestination(pinnedSource{Kind:"device",URL:"https://github.com/LineageOS/android_device_google_coral"},"oriole")
	if err==nil{t.Fatal("expected device codename mismatch")}
}
func TestCopySourceTreeRejectsSymlinks(t *testing.T){
	root:=t.TempDir();destination:=filepath.Join(t.TempDir(),"copy")
	if err:=os.WriteFile(filepath.Join(root,"file.txt"),[]byte("ok"),0600);err!=nil{t.Fatal(err)}
	if err:=os.Symlink("/etc/passwd",filepath.Join(root,"escape"));err!=nil{t.Skipf("symlinks unavailable: %v",err)}
	if err:=copySourceTree(root,destination);err==nil{t.Fatal("expected symbolic link rejection")}
}
