package config

import (
	"os"
	"log"
	"strings"
	"net"
	"github.com/kprc/nbsnetwork/tools"
	"path"
	"encoding/json"
	"github.com/pkg/errors"
)

type FCLConfig struct {
	DBFileName string `json:"dbfilename"`
	UPLink string `json:"uplink"`
	LocalNetInterface string `json:"localnetintf"`
	Flag4g bool              `json:"flag4g"`
	DefaultIPTRule [][]string `json:"defaultiptrule"`
	UserIPTRule [][]string `json:"useriptrule"`
	Save2File bool			`json:"save2file"`
	MacAddressTBL string	`json:"macaddrtbl"`
	IPAddressTBL 	string  `json:"ipaddrtbl"`
	DhcpLeaseFile   string  `json:"dhcpleasefile"`
	CmdListenPort int       `json:"cmdlistenport"`
	CmdListenIP   string    `json:"cmdlistenip"`
}


func getInterfaceLocal() []string  {
	if intfs,err:=net.Interfaces();err!=nil || len(intfs) == 0{
		log.Fatal("Can't Get local machine network interface")
		os.Exit(1)
	}else{
		ifs:=make([]string,0)
		for _,intf:=range intfs{
			ifs = append(ifs,intf.Name)
		}

		return ifs
	}

	return nil
}

func getDefault4gUpLink() string {
	ifs:=getInterfaceLocal()
	for _,nif:=range ifs{
		if strings.Contains(nif,"ppp"){
			return nif
		}
	}

	return ""
}

func getDefaultLocalLanInterface() string {
	ifs:=getInterfaceLocal()
	for _,nif:=range ifs{
		if strings.Contains(nif,"wlan"){
			return nif
		}
	}

	return ""
}

func getDefaultEthUpLink() string {
	ifs:=getInterfaceLocal()
	for _,nif:=range ifs{
		if strings.Contains(nif,"enx") || strings.Contains(nif,"eth"){
			return nif
		}
	}

	return ""
}


func (fclc *FCLConfig)InitFCLConfig(laninterface,waninterface string, flag4g bool) *FCLConfig  {
	fclc.DBFileName = "fclconfig"

	if waninterface == ""{
		//do not need check the waninterface is exists, maybe the program will start first.
		if flag4g{
			waninterface = getDefault4gUpLink()
		}else{
			waninterface = getDefaultEthUpLink()
		}
	}

	if laninterface == ""{
		laninterface = getDefaultLocalLanInterface()
	}

	fclc.UPLink = waninterface
	fclc.LocalNetInterface = laninterface
	fclc.Flag4g = flag4g
	fclc.MacAddressTBL = "accept_mac_address"
	fclc.IPAddressTBL = "accept_ip_address"
	fclc.DhcpLeaseFile = "/var/lib/misc/dnsmasq.leases"
	fclc.CmdListenPort = 9527
	fclc.CmdListenIP = "127.0.0.1"

	fclc.DefaultIPTRule = [][]string{
		{"-t ","filter","-P","FORWARD","DROP"},
		{"-t ","nat","-A","POSTROUTING","-o",waninterface,"-j","MASQUERADE"},
		{"-t ","filter","-N",fclc.IPAddressTBL},
		{"-t ","filter","-N",fclc.MacAddressTBL},
		{"-t ","filter","-A","FORWARD","-i",waninterface,"-o",laninterface,"-j",fclc.IPAddressTBL},
		{"-t ","filter","-A","FORWARD","-i",laninterface,"-o",waninterface,"-j",fclc.MacAddressTBL},
	}

	fclc.UserIPTRule = make([][]string,0)

	return fclc
}


func (fclc *FCLConfig)Load() (*FCLConfig,error) {
	curdir,err:=os.Getwd()
	if err!=nil{
		log.Fatal("Can't get current directory")
		os.Exit(1)
	}

	fclrootdir:=path.Join(curdir,".fcl")

	if !tools.FileExists(fclrootdir) || !tools.FileExists(path.Join(fclrootdir,"fcl.config")){
		log.Println("No Config File:",path.Join(fclrootdir,"fcl.config"))
		return nil,errors.New("No Config File")
	}


	bfcl,err:=tools.OpenAndReadAll(path.Join(fclrootdir,"fcl.config"))
	if err!=nil{
		log.Println("Read config file error")
		return nil,errors.New("Read config file error")
	}
	fclcload:=&FCLConfig{}

	err=json.Unmarshal(bfcl,fclcload)
	if err!=nil{
		log.Fatal("")
		os.Exit(1)
	}
	*fclc = *fclcload

	return fclcload,nil
}

func (fclc *FCLConfig)Save()  {
	curdir,err:=os.Getwd()
	if err!=nil{
		log.Fatal("Can't get current directory")
		os.Exit(1)
	}

	fclrootdir:=path.Join(curdir,".fcl")

	if !tools.FileExists(fclrootdir){
		os.MkdirAll(fclrootdir,0755)
	}

	var bcfg []byte

	bcfg,err=json.MarshalIndent(fclc,"","\t")
	if err!=nil{
		log.Fatal("Can't Save Config File")
		os.Exit(1)
	}

	tools.Save2File(bcfg,path.Join(fclrootdir,"fcl.config"))
}



func (fclc *FCLConfig)AddUserIPTRule(rule []string) error {
	if len(rule) == 0{
		return errors.New("Rule is empty")
	}

	for _,r:=range fclc.UserIPTRule{
		if len(r) == len(rule){
			flag:=true
			for i,seg:=range r{
				if seg != rule[i]{
					flag=false
					break
				}
			}
			if flag{
				return errors.New("rule duplicate")
			}
		}

	}

	fclc.UserIPTRule = append(fclc.UserIPTRule,rule)

	return nil

}

func (fclc *FCLConfig)AddUserIPTRule2(ipaddr,macaddr string) {
	if ipaddr != ""{
		rule:=[]string{"-t","filter","-A",fclc.IPAddressTBL,"-d",ipaddr,"-j","ACCEPT"}
		fclc.AddUserIPTRule(rule)
	}

	if macaddr != ""{
		rule :=[]string{"-t","filter","-A",fclc.MacAddressTBL,"-m","mac","--source-mac",macaddr,"-j","ACCEPT"}
		fclc.AddUserIPTRule(rule)
	}
}

func (fclc *FCLConfig)DelUserIPTRule(rule []string) (int,error){
	if len(rule) == 0{
		return -1,errors.New("rule is empty")
	}

	idx:=-1
	for i,r:=range fclc.UserIPTRule{
		if len(r) == len(rule){
			flag:=true
			for j,seg:=range r{
				if seg != rule[j]{
					flag=false
					break
				}
			}
			if flag{
				idx = i
				break
			}
		}

	}

	if idx >= 0{
		for ; idx< len(fclc.UserIPTRule)-1; idx++{
			fclc.UserIPTRule[idx]=fclc.UserIPTRule[idx+1]
		}
		fclc.UserIPTRule = fclc.UserIPTRule[:idx]

		return idx,nil
	}

	return -1,errors.New("Can't find rule")
}

func (fclc *FCLConfig)DelUserIPTRuleByIPAddr(ipaddr string) (int,error) {
	if ipaddr != ""{
		rule:=[]string{"-t","filter","-A",fclc.IPAddressTBL,"-d",ipaddr,"-j","ACCEPT"}
		return fclc.DelUserIPTRule(rule)
	}
	return -1,errors.New("ipaddr is empty")
}


func (fclc *FCLConfig)DelUserIPTRuleByMacAddr(macaddr string) (int,error) {
	if macaddr!=""{
		rule :=[]string{"-t","filter","-A",fclc.MacAddressTBL,"-m","mac","--source-mac",macaddr,"-j","ACCEPT"}
		return  fclc.DelUserIPTRule(rule)
	}
	return -1,errors.New("macaddr is empty")
}