package main

import (
	"github.com/kprc/flowsharectrl/config"
	"github.com/kprc/flowsharectrl/control"
	"fmt"
)

func main()  {
	//dli:=control.GetDhcpLeaseInst()
	//
	//dli.ReloadDhcpLease()
	//dli.ReloadDhcpLease()
	//
	//dli.Print()

	//ipt,_:=iptables.New()
	////
	////fmt.Println(ipt.ListChains("filter"))
	//
	////r,_:=ipt.ListWithCounters("filter","FORWARD")
	////
	////fmt.Println(r)
	////
	//s,_:=ipt.StructuredStats("filter","FORWARD")
	//
	//fmt.Println(s)
	//
	//l,_:=ipt.List("filter","FORWARD")
	//
	//fmt.Println(l)

	//control.GetFCListInst().Accept("abcdefghijklmnopqrst","11:22:33:44:55")

	fclc:=&config.FCLConfig{}
	if _,err:=fclc.Load();err!=nil{
		fclc.InitFCLConfig("","",false)
		fclc.Save()
	}

	fcl:=control.GetFCListInst()
	fcl.Accept("aaa","a0:88:b4:a3:d7:ac","172.168.100.171")
	fcl.AcceptByIP("bbb","172.168.100.62")
	fcl.AcceptByMac("ccc","8c:85:90:d1:70:f2")
	//fcl.Deny("aaa")
	fmt.Println(fcl.GetDownBytes("aaa"))
	fmt.Println(fcl.GetDownBytes("bbb"))
	fmt.Println(fcl.GetDownBytes("ccc"))




}



