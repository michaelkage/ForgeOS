//go:build linux

package agent

import "testing"

func TestRejectsPrivateReservedAndMetadataEgress(t *testing.T) {
	for _,raw:=range []string{"0.0.0.0/8","10.0.0.0/8","100.64.0.0/10","127.0.0.0/8","169.254.0.0/16","172.16.0.0/12","192.168.0.0/16","198.18.0.0/15","224.0.0.0/4","240.0.0.0/4","0.0.0.0/0"} {
		if err:=validateEgressCIDR(raw);err==nil{t.Fatalf("expected %s to be denied",raw)}
	}
}
func TestRejectsIPv6Egress(t *testing.T){
	if err:=validateEgressCIDR("2001:4860:4860::8888/128");err==nil{t.Fatal("expected IPv6 egress to be denied")}
}
func TestAllowsExplicitPublicIPv4Egress(t *testing.T){
	for _,raw:=range []string{"8.8.8.0/24","1.1.1.1/32","140.82.112.0/20"}{if err:=validateEgressCIDR(raw);err!=nil{t.Fatalf("expected %s to be allowed: %v",raw,err)}}
}
