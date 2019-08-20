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
	cusor *db.DBCusor
}

var (
	iptdbinst *IptDb
	iptdbinstlock sync.Mutex

	quit chan int
	wg *sync.WaitGroup
)

func newIptDb() *IptDb {
	curdir,err:=tools.Home()
	if err!=nil{
		log.Fatal("Can't get current directory")
		os.Exit(1)
	}

	fclrootdir:=path.Join(curdir,".fcl")
	if !tools.FileExists(fclrootdir){
		os.MkdirAll(fclrootdir,0755)
	}

	iptdb:=db.NewFileDb(path.Join(fclrootdir,"ipt.db")).Load()

	return &IptDb{NbsDbInter:iptdb}
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
	if _,err:=(*id).Find(appid);err==nil{
		return err
	}

	if bfc,err:=json.Marshal(*fc);err!=nil{
		return  err
	}else{
		return (*id).Insert(appid,string(bfc))
	}
}


func (id *IptDb)DBUpdate(appid string, fc *FlowControl) (old *FlowControl,err error){
	var v string
	v,err=(*id).Find(appid)
	if  err!=nil{
		return
	}
	old = &FlowControl{}
	err = json.Unmarshal([]byte(v),old)
	if err!=nil{
		return
	}

	var bfc []byte
	bfc,err=json.Marshal(*fc)
	if err!=nil{
		return
	}

	(*id).Update(appid,string(bfc))

	return
}

func (id *IptDb)DBDel(appid string) (del *FlowControl, err error)  {
	var v string
	v,err=(*id).Find(appid)
	if  err!=nil{
		return
	}

	del = &FlowControl{}
	err = json.Unmarshal([]byte(v),del)
	if err!=nil{
		return
	}

	(*id).Delete(appid)

	return
}

func (id *IptDb)DBSave()  {
	(*id).Save()
}

func (id *IptDb)Iterator()  {
	id.cusor = (*id).DBIterator()
}

func (id *IptDb)Next() (k string,fc *FlowControl){
	if id.cusor == nil{
		return
	}
	k,v:=id.cusor.Next()
	if k==""{
		return "",nil
	}
	fc = &FlowControl{}
	err := json.Unmarshal([]byte(v),fc)
	if err!=nil{
		return "",nil
	}

	return k,fc
}
