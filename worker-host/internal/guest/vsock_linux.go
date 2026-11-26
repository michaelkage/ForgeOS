//go:build linux

package guest

import (
	"errors"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"
)

const afVsock=40
const vmaddrCIDAny=0xffffffff

type sockaddrVM struct{Family uint16;Reserved uint16;Port uint32;CID uint32;Flags uint8;Zero [3]uint8}
type vsockListener struct{net.Listener}
func (v *vsockListener) SetDeadline(t time.Time)error{if d,ok:=v.Listener.(interface{SetDeadline(time.Time)error});ok{return d.SetDeadline(t)};return errors.New("vsock listener does not support deadlines")}

func listenVsock(port uint32)(net.Listener,error){
	fd,err:=syscall.Socket(afVsock,syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC,0);if err!=nil{return nil,err}
	addr:=sockaddrVM{Family:afVsock,Port:port,CID:vmaddrCIDAny}
	_,_,errno:=syscall.Syscall(syscall.SYS_BIND,uintptr(fd),uintptr(unsafe.Pointer(&addr)),unsafe.Sizeof(addr))
	if errno!=0{_ = syscall.Close(fd);return nil,errno}
	if err:=syscall.Listen(fd,1);err!=nil{_ = syscall.Close(fd);return nil,err}
	file:=os.NewFile(uintptr(fd),"forgeos-vsock-listener")
	listener,err:=net.FileListener(file);_ = file.Close();if err!=nil{return nil,err}
	return &vsockListener{Listener:listener},nil
}
