package main

import (
	"github.com/kprc/flowsharectrl/config"
	"github.com/kprc/flowsharectrl/control"
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
		fclc.InitFCLConfig("","",true)
		fclc.Save()
	}

	fcl:=control.GetFCListInst()
	fcl.Accept("aaa","mac","ip")
	fcl.Deny("aaa")
	fcl.GetDownBytes("aaa")



}



