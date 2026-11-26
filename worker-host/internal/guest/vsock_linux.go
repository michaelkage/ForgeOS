//go:build linux

package guest

import (
	"net"
	"syscall"
	"time"
	"unsafe"
)

const afVsock=40
const vmaddrCIDAny=0xffffffff

type sockaddrVM struct{Family uint16;Reserved uint16;Port uint32;CID uint32;Flags uint8;Zero [3]uint8}
type vsockAddr struct{cid,port uint32}
func (a vsockAddr) Network()string{return "vsock"}
func (a vsockAddr) String()string{return "cid:"+itoa(a.cid)+"/port:"+itoa(a.port)}

type vsockListener struct{fd int;port uint32}
func listenVsock(port uint32)(net.Listener,error){
	fd,err:=syscall.Socket(afVsock,syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC,0);if err!=nil{return nil,err}
	addr:=sockaddrVM{Family:afVsock,Port:port,CID:vmaddrCIDAny}
	_,_,errno:=syscall.Syscall(syscall.SYS_BIND,uintptr(fd),uintptr(unsafe.Pointer(&addr)),unsafe.Sizeof(addr))
	if errno!=0{_ = syscall.Close(fd);return nil,errno}
	if err:=syscall.Listen(fd,1);err!=nil{_ = syscall.Close(fd);return nil,err}
	return &vsockListener{fd:fd,port:port},nil
}
func (l *vsockListener) Accept()(net.Conn,error){
	for{fd,_,errno:=syscall.Syscall6(syscall.SYS_ACCEPT4,uintptr(l.fd),0,0,uintptr(syscall.SOCK_CLOEXEC),0,0);if errno==syscall.EINTR{continue};if errno!=0{return nil,errno};return &vsockConn{fd:int(fd)},nil}
}
func (l *vsockListener) Close()error{return syscall.Close(l.fd)}
func (l *vsockListener) Addr()net.Addr{return vsockAddr{cid:vmaddrCIDAny,port:l.port}}
func (l *vsockListener) SetDeadline(t time.Time)error{var tv syscall.Timeval;if !t.IsZero(){d:=time.Until(t);if d<=0{d=time.Millisecond};tv=syscall.NsecToTimeval(d.Nanoseconds())};return syscall.SetsockoptTimeval(l.fd,syscall.SOL_SOCKET,syscall.SO_RCVTIMEO,&tv)}

type vsockConn struct{fd int}
func (c *vsockConn) Read(p []byte)(int,error){for{n,err:=syscall.Read(c.fd,p);if err==syscall.EINTR{continue};return n,err}}
func (c *vsockConn) Write(p []byte)(int,error){for{n,err:=syscall.Write(c.fd,p);if err==syscall.EINTR{continue};return n,err}}
func (c *vsockConn) Close()error{return syscall.Close(c.fd)}
func (c *vsockConn) LocalAddr()net.Addr{return vsockAddr{}}
func (c *vsockConn) RemoteAddr()net.Addr{return vsockAddr{}}
func (c *vsockConn) SetDeadline(t time.Time)error{return c.setTimeout(t,syscall.SO_RCVTIMEO,syscall.SO_SNDTIMEO)}
func (c *vsockConn) SetReadDeadline(t time.Time)error{return c.setTimeout(t,syscall.SO_RCVTIMEO)}
func (c *vsockConn) SetWriteDeadline(t time.Time)error{return c.setTimeout(t,syscall.SO_SNDTIMEO)}
func (c *vsockConn) setTimeout(t time.Time,opts ...int)error{
	var tv syscall.Timeval
	if !t.IsZero(){d:=time.Until(t);if d<=0{d=time.Millisecond};tv=syscall.NsecToTimeval(d.Nanoseconds())}
	for _,opt:=range opts{if err:=syscall.SetsockoptTimeval(c.fd,syscall.SOL_SOCKET,opt,&tv);err!=nil{return err}}
	return nil
}
func itoa(v uint32)string{if v==0{return "0"};var b [10]byte;i:=len(b);for v>0{i--;b[i]=byte('0'+v%10);v/=10};return string(b[i:])}
