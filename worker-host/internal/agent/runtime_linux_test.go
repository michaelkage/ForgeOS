//go:build linux

package agent

import (
	"net/netip"
	"testing"
)

func TestRejectsPrivateAndMetadataEgress(t *testing.T) {
	for _,raw:=range []string{"0.0.0.0/0","10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","169.254.169.254/32","127.0.0.1/32","224.0.0.0/4"} {
		p:=netip.MustParsePrefix(raw)
		if !isForbiddenEgress(p){t.Fatalf("expected %s to be denied",raw)}
	}
}

func TestAllowsPublicEgress(t *testing.T) {
	for _,raw:=range []string{"8.8.8.0/24","1.1.1.1/32","140.82.112.0/20"} {
		p:=netip.MustParsePrefix(raw)
		if isForbiddenEgress(p){t.Fatalf("expected %s to be allowed",raw)}
	}
}

func TestRejectsNonIPv4PolicyInConstructor(t *testing.T) {
	_,err:=NewLinuxRuntime(LinuxConfig{
		StateDir:"/var/lib/forgeos",ChrootBase:"/srv/forgeos",CgroupParent:"forgeos.slice",
		JailerPath:"/usr/bin/jailer",FirecrackerPath:"/usr/bin/firecracker",
		VMMUIDBase:20000,VMMGIDBase:20000,IOBytesPerSecond:1<<20,
		BootstrapAPIBaseURL:"https://forgeos.example",
		EgressPolicies:map[string][]string{"public":{"2001:4860:4860::8888/128"}},
		DNSResolvers:[]string{"1.1.1.1"},
	})
	if err==nil{t.Fatal("expected IPv6 egress policy to be rejected")}
}
