package cmd

import (
	"google.golang.org/grpc"
	"context"
)

type CmdConn struct {
	c *grpc.ClientConn
	ctx context.Context
	cancel context.CancelFunc
}

func DialToCmdService(addr string) *CmdConn  {
	if addr == ""{
		addr="127.0.0.1"
	}

	//remoteaddr:=addr+":"

	return nil
}


