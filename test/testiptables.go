package main

import (
	"github.com/kprc/flowsharectrl/control"
	"github.com/coreos/go-iptables/iptables"
	"fmt"
)

func main()  {
	dli:=control.GetDhcpLeaseInst()

	dli.ReloadDhcpLease()
	dli.ReloadDhcpLease()

	dli.Print()

	ipt,_:=iptables.New()

	fmt.Println(ipt.ListChains("filter"))

	r,_:=ipt.ListWithCounters("filter","FORWARD")

	fmt.Println(r)

	s,_:=ipt.StructuredStats("filter","accept_ip_address")

	fmt.Println(s)

}



