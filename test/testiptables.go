package main

import (
	"github.com/kprc/flowsharectrl/config"
	"github.com/kprc/flowsharectrl/control"
	"fmt"
)

func main()  {

	config.GetConfigInstanceByParam("wlan0","",false)

	fcl:=control.GetFCListInst()
	//fcl.Accept("aaa","a0:88:b4:a3:d7:ac","172.168.100.171")
	//fcl.AcceptByIP("bbb","172.168.100.62")
	fcl.AcceptByMac("ccc","8c:85:90:d1:70:f2")
	////fcl.Deny("aaa")

	//time.Sleep(time.Second*30)

	//fmt.Println(fcl.GetDownBytes("aaa"))
	//fmt.Println(fcl.GetDownBytes("bbb"))
	fmt.Println(fcl.GetDownBytes("ccc"))

	fmt.Println(fcl.ListFCS())

}



