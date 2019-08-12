package control

import (
	"github.com/kprc/nbsnetwork/common/list"
	"sync"
	"github.com/coreos/go-iptables/iptables"
	"log"
	"github.com/kprc/flowsharectrl/config"
	"strings"
	"golang.org/x/tools/go/ssa/interp/testdata/src/os"
)

type FlowControl struct {
	AppId string			`json:"appid"`
	MacAddr string			`json:"macaddr"`
	IpAddr string			`json:"ipaddr"`
	HostName string			`json:"hostname"`
	IsShare bool			`json:"isshare"`
	UpBytes int64			`json:"-"`
	DownBytes int64			`json:"-"`
}


type FCList struct {
	list.List
	listrwlock sync.RWMutex
	tbl *iptables.IPTables
	tblLock sync.Mutex
	cfg *config.FCLConfig
	cfglock sync.Mutex
}

type FCInter interface {
	InitIPTL()
	Accept(appid,mac_addr,ipaddr string) error
	AcceptByMac(appid,macaddr string) error
	AcceptByIP(appid,ipaddr string) error
	Deny(appid string)
	GetUpBytes(appid string) int64
	GetDownBytes(appid string) int64
}

type KeyInter interface {
	GetKey() string
}

var (
	fcListInst FCInter
	fcListInstLock sync.Mutex
)

var (
	gIPTTblNames = []string{"nat","filter","mangle","raw"}
	gIPTDftChainNames = map[string]struct{}{
	"PREROUTING": struct{}{},
	"INPUT": struct{}{},
	"FORWARD": struct{}{},
	"OUTPUT": struct{}{},
	"POSTROUTING": struct{}{}}
)

func getKey(v interface{}) string  {
	switch v.(type) {
	case string:
		return v.(string)
	default:
		return v.(KeyInter).GetKey()

	}
}


func newFCList() *FCList {
	l:=list.NewList(func(v1 interface{}, v2 interface{}) int {
		k1,k2:=getKey(v1),getKey(v2)
		if k1==k2{
			return 0
		}
		return 1
	})

	return &FCList{List:l}
}

func GetFCListInst() FCInter  {
	if fcListInst == nil{
		fcListInstLock.Lock()
		defer fcListInstLock.Unlock()

		if fcListInst == nil{
			fcListInst = newFCList()
		}

	}

	return fcListInst
}


func (fc *FlowControl)GetKey() string  {
	return fc.AppId
}

func (fcl *FCList)initApply()  {
	defaultrules:=fcl.cfg.DefaultIPTRule

	for _,dftrule:=range defaultrules{
		if strings.TrimSpace(dftrule[2]) == "-A"{
			fcl.tbl.Append(dftrule[1],dftrule[3],strings.Join(dftrule[4:]," "))
		}
		if strings.TrimSpace(dftrule[2]) == "-P"{
			fcl.tbl.ChangePolicy(dftrule[1],dftrule[3],strings.Join(dftrule[4:]," "))
		}
		if strings.TrimSpace(dftrule[2]) == "-N"{
			fcl.tbl.NewChain(dftrule[1],dftrule[3])
		}
	}

	for _,rule:=range fcl.cfg.UserIPTRule{
		fcl.tbl.Append(rule[1],rule[3],strings.Join(rule[4:]," "))
	}

}

func (fcl *FCList)initTbl()  {
	for _,tblname := range gIPTTblNames{
		chains,err:=fcl.tbl.ListChains(tblname)
		if err==nil{
			for _,chain:=range chains{
				fcl.tbl.ClearChain(tblname,chain)
			}
		}
	}
	for _,tblname := range gIPTTblNames{
		chains,err:=fcl.tbl.ListChains(tblname)
		if err==nil{
			for _,chain:=range chains{
				if _,ok:=gIPTDftChainNames[chain];!ok{
					fcl.tbl.DeleteChain(tblname,chain)
				}
			}
		}
	}

	fcl.cfglock.Lock()
	defer fcl.cfglock.Unlock()

	if fcl.cfg == nil{
		fcl.cfg = &config.FCLConfig{}
		if _,err:=fcl.cfg.Load();err!=nil{
			log.Fatal("Load Config file error")
			os.Exit(1)
		}
	}
	fcl.initApply()
}

func (fcl *FCList)InitIPTL()  {
	fcl.tblLock.Lock()
	defer fcl.tblLock.Unlock()
	if fcl.tbl != nil{
		return
	}

	var err error
	if fcl.tbl,err = iptables.New();err!=nil{
		log.Fatal("Can't Create iptables")
		return
	}

	fcl.initTbl()
}

func (fcl *FCList)Accept(appid,mac_addr,ipaddr string) error  {

	return nil
}

func (fcl *FCList)AcceptByIP(appid,ipaddr string) error  {

	return nil
}

func (fcl *FCList)AcceptByMac(appid,macaddr string) error {

	return nil
}


func (fcl *FCList)Deny(appid string)  {

}

func (fcl *FCList)GetUpBytes(appid string) int64  {
	return 0
}

func (fcl *FCList)GetDownBytes(appid string) int64  {
	return 0
}

