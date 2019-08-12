package control

import (
	"github.com/kprc/nbsnetwork/common/list"
	"sync"
	"github.com/coreos/go-iptables/iptables"
	"log"
	"github.com/kprc/flowsharectrl/config"
	"strings"
	"os"
	"bufio"
	"io"
	"github.com/pkg/errors"
)

type FlowControl struct {
	AppId string			`json:"appid"`
	MacAddr string			`json:"macaddr"`
	IpAddr string			`json:"ipaddr"`
	HostName string			`json:"hostname"`
	IsShare bool			`json:"isshare"`
	UpBytes uint64			`json:"-"`
	DownBytes uint64			`json:"-"`
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
	Accept(appid,mac_addr,ipaddr string) error
	AcceptByMac(appid,macaddr string) error
	AcceptByIP(appid,ipaddr string) error
	Deny(appid string)
	GetUpBytes(appid string) uint64
	GetDownBytes(appid string) uint64
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

	fcl:= &FCList{List:l}
	fcl.initIPTL()

	return fcl
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

func (fcl *FCList)applyDel(fc *FlowControl) error  {

	var err error

	if fc.MacAddr != ""{
		err=fcl.tbl.Delete("filter",
			fcl.cfg.MacAddressTBL,
			"-m mac --mac-source ",fc.MacAddr," -j ACCEPT")
		if err!=nil{
			log.Println(err)
		}

	}

	if fc.IpAddr != ""{
		err1:=fcl.tbl.Delete("filter",
			fcl.cfg.IPAddressTBL,
			"-d ",fc.IpAddr," -j ACCEPT")
		if err1!=nil{
			log.Println(err1)
		}
		if err == nil{
			err = err1
		}
	}

	return err
}

func (fcl *FCList)applyAppend(fc *FlowControl) error  {
	var err error
	if fc.MacAddr != ""{
		err = fcl.tbl.Append("filter",
			fcl.cfg.MacAddressTBL,
			"-m mac --mac-source",fc.MacAddr," -j ACCEPT")
		if err!=nil{
			log.Println(err)
		}
	}

	if fc.IpAddr != ""{
		err1:=fcl.tbl.Append("filter",fcl.cfg.IPAddressTBL,
			"-d ",fc.IpAddr, " -j ACCEPT")
		if err1!=nil{
			log.Println(err1)
			if err == nil{
				err = err1
			}
		}
	}


	return err
}

func (fcl *FCList)getUPBytes(macaddr string) uint64  {
	uppermacaddr:=strings.ToUpper(macaddr)

	if arrs,err:=fcl.tbl.StructuredStats("filter",fcl.cfg.MacAddressTBL);err!=nil{
		return 0
	}else{
		for _,s:=range arrs{
			if s.Options[4:] == uppermacaddr{
				return s.Bytes
			}
		}
	}

	return 0
}

func (fcl *FCList)getDownByes(ipaddr string) uint64  {
	if arrs,err:=fcl.tbl.StructuredStats("filter",fcl.cfg.IPAddressTBL);err!=nil{
		return 0
	}else{
		for _,s:=range arrs{
			if s.Destination.IP.String() == ipaddr{
				return s.Bytes
			}
		}
	}

	return 0
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

func (fcl *FCList)initApplyTbl()  {
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
	fcl.recover()
}

func (fcl *FCList)initIPTL()  {
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

	fcl.initApplyTbl()
}

func (fcl *FCList)recover()  {
	//load from db, and apply all
}

func (fcl *FCList)Accept(appid,mac_addr,ipaddr string) error  {
	fc:=&FlowControl{}
	fc.AppId = appid
	fc.IsShare = true

	fc.MacAddr = strings.ToUpper(mac_addr)
	fc.IpAddr = ipaddr

	r,err:=fcl.FindDo(fc, func(arg interface{}, v interface{}) (ret interface{}, err error) {
		fc1:=arg.(*FlowControl)
		fc2:=v.(*FlowControl)

		if fc1.MacAddr == fc2.MacAddr && fc1.IpAddr == fc1.IpAddr{
			return
		}

		fc3:=&FlowControl{}
		*fc3=*fc2

		*fc2=*fc1

		ret = fc3

		return
	})
	if err!=nil{
		fcl.AddValue(fc)
	}

	if r!=nil{
		fcl.applyDel(r.(*FlowControl))
	}

	if err!=nil || r!=nil{
		fcl.applyAppend(fc)
	}

	//GetIPTDBInstant().DBUpdate()


	return nil
}

func (fcl *FCList)AcceptByIP(appid,ipaddr string) error  {

	var upmacaddr string
	//var hostname string
	f,err:=os.OpenFile(fcl.cfg.DhcpLeaseFile,os.O_RDONLY,0644)
	if err!=nil{
		return err
	}

	bf:=bufio.NewReader(f)

	for{
		if line,_,err:=bf.ReadLine(); err!=nil{
			if err == io.EOF {
				break
			}

			if err == bufio.ErrBufferFull {
				return errors.New("Buffer full")
			}

			if len(line) > 0 {
				//pending drop it
				return errors.New("Reading pending")
			}
		}else{
			if len(line) > 0{
				leasearr:=strings.Split(string(line)," ")
				if len(leasearr) >3{
					if ipaddr == leasearr[2]{
						upmacaddr = strings.ToUpper(leasearr[1])
						//hostname = leasearr[3]
						break
					}
				}
			}
		}
	}

	if upmacaddr == ""{
		return  errors.New("Client not found")
	}

	return fcl.Accept(appid,upmacaddr,ipaddr)
}

func (fcl *FCList)AcceptByMac(appid,macaddr string) error {
	lomacaddr:=strings.ToLower(macaddr)
	var ipaddr string

	f,err:=os.OpenFile(fcl.cfg.DhcpLeaseFile,os.O_RDONLY,0644)
	if err!=nil{
		return err
	}

	bf:=bufio.NewReader(f)

	for{
		if line,_,err:=bf.ReadLine(); err!=nil{
			if err == io.EOF {
				break
			}

			if err == bufio.ErrBufferFull {
				return errors.New("Buffer full")
			}

			if len(line) > 0 {
				//pending drop it
				return errors.New("Reading pending")
			}
		}else{
			if len(line) > 0{
				leasearr:=strings.Split(string(line)," ")
				if len(leasearr) >3{
					if lomacaddr == strings.ToLower(leasearr[1]){
						ipaddr = leasearr[2]
						break
					}
				}
			}
		}
	}

	if ipaddr == ""{
		return  errors.New("Client not found")
	}
	return fcl.Accept(appid,upmacaddr,ipaddr)
}


func (fcl *FCList)Deny(appid string)  {
	r,err:=fcl.FindDo(appid, func(arg interface{}, v interface{}) (ret interface{}, err error) {
		return v,nil
	})

	if err!=nil{
		return
	}
	if r!=nil{
		fcl.applyDel(r.(*FlowControl))
	}

	fcl.DelValue(appid)

}

func (fcl *FCList)GetUpBytes(appid string) uint64  {
	r,err:=fcl.FindDo(appid, func(arg interface{}, v interface{}) (ret interface{}, err error) {
		return v,nil
	})

	if err!=nil{
		return 0
	}

	bytecnt:=fcl.getUPBytes(r.(*FlowControl).MacAddr)
	r.(*FlowControl).UpBytes = bytecnt

	//update
	//
	//fcl.FindDo(r, func(arg interface{}, v interface{}) (ret interface{}, err error) {
	//	p1:=arg.(*FlowControl)
	//	p2:=v.(*FlowControl)
	//
	//	p2.UpBytes = p1.UpBytes
	//
	//	return
	//})

	return bytecnt
}

func (fcl *FCList)GetDownBytes(appid string) uint64  {
	r,err:=fcl.FindDo(appid, func(arg interface{}, v interface{}) (ret interface{}, err error) {
		return v,nil
	})

	if err!=nil{
		return 0
	}

	bytecnt:=fcl.getDownByes(r.(*FlowControl).IpAddr)
	r.(*FlowControl).DownBytes = bytecnt


	return bytecnt
}

