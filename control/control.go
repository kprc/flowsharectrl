package control

import (
	"strings"
	"os"
	"bufio"
	"io"
	"sync"
	"log"
	"fmt"
	"github.com/kprc/nbsnetwork/common/list"
	"github.com/coreos/go-iptables/iptables"
	"github.com/kprc/flowsharectrl/config"
	"github.com/pkg/errors"
)

type FlowControl struct {
	AppId 		string			`json:"appid"`
	MacAddr	 	string			`json:"macaddr"`
	IpAddr 		string			`json:"ipaddr"`
	HostName 	string			`json:"hostname"`
	IsShare 	bool			`json:"isshare"`
	UpBytes 	uint64			`json:"-"`
	DownBytes 	uint64			`json:"-"`
}


type FCList struct {
	list.List
	listrwlock sync.RWMutex
	tbl *iptables.IPTables
	tblLock sync.Mutex
	cfg *config.FCLConfig
	cfglock sync.Mutex
	leaseFileLock sync.Mutex
}

type FCInter interface {
	Accept(appID,macAddr,ipAddr string) error
	AcceptByMac(appID,macAddr string) error
	AcceptByIP(appID,ipAddr string) error
	Deny(appID string)
	ListFCS() [][]string
	GetUpBytes(appID string) (uint64,error)
	GetDownBytes(appID string) (uint64,error)
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

	fcl.tblLock.Lock()
	defer fcl.tblLock.Unlock()

	if fc.MacAddr != ""{
		err=fcl.tbl.Delete("filter",
			fcl.cfg.MacAddressTBL,
			"-m","mac","--mac-source",fc.MacAddr,"-j","ACCEPT")
		if err!=nil{
			log.Println(err)
		}

	}

	if fc.IpAddr != ""{
		err1:=fcl.tbl.Delete("filter",
			fcl.cfg.IPAddressTBL,
			"-d",fc.IpAddr,"-j","ACCEPT")
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

	fcl.tblLock.Lock()
	defer fcl.tblLock.Unlock()

	return fcl.applyAppendWithoutLock(fc)
}

func (fcl *FCList)applyAppendWithoutLock(fc *FlowControl) error    {
	var err error
	if fc.MacAddr != ""{
		err = fcl.tbl.Append("filter",
			fcl.cfg.MacAddressTBL,
			"-m","mac","--mac-source",fc.MacAddr,"-j","ACCEPT")
		if err!=nil{
			log.Println(err)
		}
	}

	if fc.IpAddr != ""{
		err1:=fcl.tbl.Append("filter",fcl.cfg.IPAddressTBL,
			"-d",fc.IpAddr, "-j","ACCEPT")
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

	fcl.tblLock.Lock()
	defer fcl.tblLock.Unlock()
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
	fcl.tblLock.Lock()
	defer fcl.tblLock.Unlock()
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
		//fmt.Println(idx,dftrule)
		if strings.TrimSpace(dftrule[2]) == "-A"{
			err:=fcl.tbl.Append(dftrule[1],dftrule[3],dftrule[4:]...)
			if err!=nil{
				fmt.Println(err)
			}
		}
		if strings.TrimSpace(dftrule[2]) == "-P"{
			err:=fcl.tbl.ChangePolicy(dftrule[1],dftrule[3],strings.Join(dftrule[4:]," "))
			if err!=nil{
				fmt.Println(err)
			}
		}
		if strings.TrimSpace(dftrule[2]) == "-N"{
			err:=fcl.tbl.NewChain(dftrule[1],dftrule[3])
			if err!=nil{
				fmt.Println(err)
			}
		}
	}

	for _,rule:=range fcl.cfg.UserIPTRule{
		//fmt.Println(idx,rule)
		err:=fcl.tbl.Append(rule[1],rule[3],rule[4:]...)
		if err!=nil{
			fmt.Println(err)
		}

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
		fcl.cfg = config.GetConfigInstance()
	}
	fcl.initApply()

	if fcl.cfg.Save2File {
		fcl.recover()
	}

	GetIPTDBInstant().Save()
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
	iptdb:=GetIPTDBInstant()
	iptdb.Iterator()

	for {
		k,fc:=iptdb.Next()
		if k=="" || fc == nil{
			break
		}
		fcl.AddValue(fc)
		fcl.applyAppendWithoutLock(fc)
	}
}

func (fcl *FCList)Accept(appID,macAddr,ipAddr string) error  {
	fc:=&FlowControl{}
	fc.AppId = appID
	fc.IsShare = true
	fc.MacAddr = strings.ToUpper(macAddr)
	fc.IpAddr = ipAddr

	fcl.listrwlock.Lock()
	defer fcl.listrwlock.Unlock()

	r,err:=fcl.FindDo(fc, func(arg interface{}, v interface{}) (ret interface{}, err error) {
		fc1:=arg.(*FlowControl)
		fc2:=v.(*FlowControl)
		if fc1.MacAddr == fc2.MacAddr && fc1.IpAddr == fc2.IpAddr{
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

	iptbldb:=GetIPTDBInstant()
	if _,err:=iptbldb.Find(appID);err!=nil{
		iptbldb.DBInsert(appID,fc)
	}else{
		iptbldb.DBUpdate(appID,fc)
	}


	return nil
}

func (fcl *FCList)AcceptByIP(appID,ipAddr string) error  {

	var upmacaddr string

	fcl.leaseFileLock.Lock()
	defer fcl.leaseFileLock.Unlock()
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
				return errors.New("Reading pending")
			}
		}else{
			if len(line) > 0{
				leasearr:=strings.Split(string(line)," ")
				if len(leasearr) >3{
					if ipAddr == leasearr[2]{
						upmacaddr = strings.ToUpper(leasearr[1])
						//hostname = leasearr[3]
						break
					}
				}
			}
		}
	}
	f.Close()

	if upmacaddr == ""{
		return  errors.New("Client not found")
	}

	return fcl.Accept(appID,upmacaddr,ipAddr)
}

func (fcl *FCList)AcceptByMac(appID,macAddr string) error {
	lomacaddr:=strings.ToLower(macAddr)
	var ipaddr string
	fcl.leaseFileLock.Lock()
	defer fcl.leaseFileLock.Unlock()

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
	return fcl.Accept(appID,lomacaddr,ipaddr)
}


func (fcl *FCList)Deny(appID string)  {
	fcl.listrwlock.Lock()
	defer fcl.listrwlock.Unlock()
	r,err:=fcl.FindDo(appID, func(arg interface{}, v interface{}) (ret interface{}, err error) {
		return v,nil
	})

	if err!=nil{
		return
	}
	if r!=nil{
		fcl.applyDel(r.(*FlowControl))
	}

	fcl.DelValue(appID)

	iptbldb:=GetIPTDBInstant()
	iptbldb.DBDel(appID)
}

//return value
// [][]string{
//    {appid,ipaddr,macaddr},
//    {appid,ipaddr,macaddr},
// }
func (fcl *FCList)ListFCS() [][]string {
	fcl.listrwlock.Lock()
	defer fcl.listrwlock.Unlock()
	cursor:=fcl.ListIterator(0)
	ret:=make([][]string,0)
	for{
		fcinter:=cursor.Next()
		if fcinter == nil{
			break
		}
		fc:=fcinter.(*FlowControl)
		fcs:=make([]string,0)
		fcs = append(fcs,fc.AppId,fc.IpAddr,fc.MacAddr)
		ret = append(ret,fcs)
	}

	return ret
}

func (fcl *FCList)GetUpBytes(appID string) (uint64,error)  {

	fcl.listrwlock.Lock()
	defer fcl.listrwlock.Unlock()
	r,err:=fcl.FindDo(appID, func(arg interface{}, v interface{}) (ret interface{}, err error) {
		return v,nil
	})

	if err!=nil{
		return 0,err
	}

	bytecnt:=fcl.getUPBytes(r.(*FlowControl).MacAddr)
	r.(*FlowControl).UpBytes = bytecnt


	return bytecnt,nil
}

func (fcl *FCList)GetDownBytes(appID string) (uint64,error)  {

	fcl.listrwlock.Lock()
	defer fcl.listrwlock.Unlock()

	r,err:=fcl.FindDo(appID, func(arg interface{}, v interface{}) (ret interface{}, err error) {
		return v,nil
	})

	if err!=nil{
		return 0,err
	}

	bytecnt:=fcl.getDownByes(r.(*FlowControl).IpAddr)
	r.(*FlowControl).DownBytes = bytecnt

	return bytecnt,nil
}

