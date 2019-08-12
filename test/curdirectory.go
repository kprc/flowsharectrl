package main

import (
	"strings"
	"path/filepath"
	"os"
	"log"
	"fmt"
	"net"
)

func substr(s string, pos, length int) string {
	runes := []rune(s)
	l := pos + length
	if l > len(runes) {
		l = len(runes)
	}
	return string(runes[pos:l])
}

func getParentDirectory(dirctory string) string {
	return substr(dirctory, 0, strings.LastIndex(dirctory, "/"))
}

func getCurrentDirectory() string {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		log.Fatal(err)
	}
	return strings.Replace(dir, "\\", "/", -1)
}

type teststruct struct{
	a string
	b []string
	c int
	d [][]string
}

func (ts *teststruct)testinit()  {
	ts1:=&teststruct{}
	ts1.a = "a"
	ts1.b = []string{"b1","b2"}
	ts1.c = 100
	ts1.d = [][]string{{"d01","d02"},{"d11","d12"},}

	*ts=*ts1

}

func (ts *teststruct)Print() {
	fmt.Println(*ts)
}

func main() {

	var str1, str2 string
	str1 = getCurrentDirectory()
	fmt.Println(str1)

	str2 = getParentDirectory(str1)
	fmt.Println(str2)

	//fmt.Println(os.Getwd())
	//
	//time.Sleep(time.Second*10)

	fmt.Println(os.Getwd())


	netintfs,err:=net.Interfaces()
	if err==nil{
		fmt.Println(netintfs)
	}

	for _,netint:=range netintfs{
		fmt.Println(netint.Name)
	}



	ts:=&teststruct{}

	ts.testinit()

	ts.Print()



}