package control

import (
	"github.com/rickeyliao/ServiceAgent/db"
	"os"
	"log"
	"path"
	"github.com/kprc/nbsnetwork/tools"
	"sync"
	"encoding/json"
)

type IptDb struct {
	db.NbsDbInter
}

var (
	iptdbinst *IptDb
	iptdbinstlock sync.Mutex

	quit chan int
	wg *sync.WaitGroup
)

func newIptDb() *IptDb {
	curdir,err:=os.Getwd()
	if err!=nil{
		log.Fatal("Can't get current directory")
		os.Exit(1)
	}

	fclrootdir:=path.Join(curdir,".fcl")
	if !tools.FileExists(fclrootdir){
		os.MkdirAll(fclrootdir,0755)
	}

	iptdb:=db.NewFileDb(path.Join(fclrootdir,"ipt.db"))

	return &IptDb{iptdb}
}

func GetIPTDBInstant() *IptDb {
	if iptdbinst == nil {
		 iptdbinstlock.Lock()
		 defer iptdbinstlock.Unlock()
		 if iptdbinst == nil{
		 	iptdbinst = newIptDb()
		 }
	}

	return iptdbinst
}

func (id *IptDb)DBInsert(appid string,fc *FlowControl) error  {
	if _,err:=id.Find(appid);err!=nil{
		return err
	}

	if bfc,err:=json.Marshal(*fc);err!=nil{
		return  err
	}else{
		return id.Insert(appid,string(bfc))
	}
}

