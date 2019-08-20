package cmd

import (
	"google.golang.org/grpc"
	"context"
	"github.com/kprc/flowsharectrl/config"
	"strconv"
	"log"
)

type CmdConn struct {
	c *grpc.ClientConn
	ctx context.Context
	cancel context.CancelFunc
	remoteaddr string
}

func DialToCmdService(addr string) *CmdConn  {
	if addr == ""{
		addr="127.0.0.1"
	}

	port:=strconv.Itoa(config.GetConfigInstance().CmdListenPort)

	remoteaddr:=addr+":"+port

	conn,err:=grpc.Dial(remoteaddr,grpc.WithInsecure())
	if err!=nil{
		log.Fatal("can not connect rpc server:", err)
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &CmdConn{
		c:      conn,
		ctx:    ctx,
		cancel: cancel,
		remoteaddr:remoteaddr,
	}

	return nil
}

func (conn *CmdConn)Close()  {
	conn.c.Close()
	conn.cancel()
}

func DefaultCmdSend(remoteaddr string,md int32)  {

}

