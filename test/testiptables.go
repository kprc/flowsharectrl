package main

import (
	"github.com/coreos/go-iptables/iptables"
	"fmt"
)

func main()  {
	//dli:=control.GetDhcpLeaseInst()
	//
	//dli.ReloadDhcpLease()
	//dli.ReloadDhcpLease()
	//
	//dli.Print()

	ipt,_:=iptables.New()
	//
	//fmt.Println(ipt.ListChains("filter"))

	//r,_:=ipt.ListWithCounters("filter","FORWARD")
	//
	//fmt.Println(r)
	//
	s,_:=ipt.StructuredStats("filter","FORWARD")

	fmt.Println(s)

	l,_:=ipt.List("filter","FORWARD")

	fmt.Println(l)

	//control.GetFCListInst().Accept("abcdefghijklmnopqrst","11:22:33:44:55")

}



