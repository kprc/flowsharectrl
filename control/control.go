package control

import (
	"sync"
	"github.com/kprc/nbsnetwork/common/list"
	"os"
	"log"
	"bufio"
	"io"
	"strings"
	"fmt"
)

type DhcpLease struct {
	MacAddress string
	IpAddress string
	HostName string
	Hour     int
	IsShare  bool
	TotalUpBytes int64
	TotalDownBytes int64
}

type keyinter interface {
	GetMacAddress() string
}

type DhcpLeaseInter interface {
	Accept(mac_addr string)
	Deny(mac_addr string)
	GetUpBytes(mac_addr string) int64
	GetDownBytes(mac_addr string) int64
	ReloadDhcpLease()
	Print()
}

type DhcpleaseList struct {
	list.List
}

var (
	dhcpleaseInst DhcpLeaseInter
	dhcpleaseLock sync.Mutex
)

func GetDhcpLeaseInst() DhcpLeaseInter {
	if dhcpleaseInst == nil{
		dhcpleaseLock.Lock()
		defer dhcpleaseLock.Unlock()
		if dhcpleaseInst == nil {
			dhcpleaseInst = newDhcpLeaseInst()
		}
	}

	return dhcpleaseInst

}

func getkey(v interface{}) string {
	switch v.(type) {
	case string:
		return v.(string)
	case keyinter:
		return v.(keyinter).GetMacAddress()

	}

	return ""
}

func newDhcpLeaseInst() DhcpLeaseInter {
	l:= list.NewList(func(v1 interface{}, v2 interface{}) int {
		d1,d2:=getkey(v1),getkey(v2)
		if d1 == d2{
			return 0
		}else{
			return 1
		}

	})

	dl:=&DhcpleaseList{List:l}


	return dl
}

func (dl *DhcpLease)GetMacAddress() string  {
	return dl.MacAddress
}

func (dl *DhcpleaseList)Accept(mac_addr string)  {
	if v:=(*dl).Find(mac_addr);v==nil{
		dl.ReloadDhcpLease()
	}

	_,err:=(*dl).FindDo(mac_addr, func(arg interface{}, v interface{}) (ret interface{}, err error) {
		node:=v.(*DhcpLease)
		node.IsShare = true

		return nil,nil
	})

	if err == nil{
		dl.applyIptables()
	}
}

func (dl *DhcpleaseList)Deny(mac_addr string)  {
	if v:=(*dl).Find(mac_addr);v==nil{
		return
	}
	_,err:=(*dl).FindDo(mac_addr, func(arg interface{}, v interface{}) (ret interface{}, err error) {
		node:=v.(*DhcpLease)
		node.IsShare = false

		return nil,nil
	})
	if err == nil{
		dl.applyIptables()
	}

}

func (dl *DhcpleaseList)GetUpBytes(mac_addr string) int64 {
	bytecnts,err:=(*dl).FindDo(mac_addr, func(arg interface{}, v interface{}) (ret interface{}, err error) {
		node:=v.(*DhcpLease)

		return  node.TotalUpBytes,nil
	})

	if err!=nil{
		return 0
	}

	if bytecnts == nil{
		return 0
	}

	return bytecnts.(int64)

}

func (dl *DhcpleaseList)GetDownBytes(mac_addr string) int64  {
	bytecnts,err:=(*dl).FindDo(mac_addr, func(arg interface{}, v interface{}) (ret interface{}, err error) {
		node:=v.(*DhcpLease)
		return  node.TotalDownBytes,nil
	})

	if err!=nil{
		return 0
	}

	if bytecnts == nil{
		return 0
	}

	return bytecnts.(int64)
}

func (dl *DhcpleaseList)ReloadDhcpLease()  {
	flag:=os.O_RDONLY

	if f,err:=os.OpenFile("/var/lib/misc/dnsmasq.leases",flag,0644);err!=nil{
		log.Fatal("Can't open dnsmasq.leases")
	}else{
		//read line by line
		dl.readlinebyline(f)
		f.Close()
	}

}

func (dl *DhcpleaseList)readlinebyline(file *os.File)  {
	bf:=bufio.NewReader(file)
	for{
		if line,_,err := bf.ReadLine(); err!=nil{
			if err == io.EOF{
				break
			}
			if err == bufio.ErrBufferFull {
				log.Fatal("Buffer full")
				break
			}
			if len(line) > 0 {
				//pending drop it
				log.Fatal("Reading pending")
				break
			}
		}else{
			if len(line)>0{
				info:=strings.Split(string(line)," ")
				if len(info) < 4{
					log.Fatal("error lease file")
					break
				}
				mac_addr:=info[1]
				if v:=(*dl).Find(mac_addr);v==nil{
					node:=&DhcpLease{MacAddress:mac_addr,IpAddress:info[2],HostName:info[3]}
					node.Hour = 12
					(*dl).AddValue(node)
				}
			}
		}
	}
}

func (dl *DhcpleaseList)Print()  {
	(*dl).Traverse("Node:  ======", func(arg interface{}, v interface{}) (ret interface{}, err error) {
		fmt.Println(arg.(string))
		node:=v.(*DhcpLease)
		fmt.Println(node.MacAddress,node.IpAddress,node.HostName,node.IsShare,node.TotalUpBytes,node.TotalDownBytes)
		return nil,nil
	})
}


func (dl *DhcpleaseList)applyIptables()  {

}


