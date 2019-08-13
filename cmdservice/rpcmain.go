package cmdservice

import (
	"google.golang.org/grpc"
	"net"
	"github.com/kprc/flowsharectrl/config"
	"fmt"
	"log"
	"google.golang.org/grpc/reflection"
)

var grpcServer *grpc.Server

func StartCmdService(cfg *config.FCLConfig) {
	l, err := net.Listen("tcp4", fmt.Sprintf("%s:%d", cfg.CmdListenIP, cfg.CmdListenPort))
	if err != nil {
		log.Fatal("Failed to listen: %v", err)
		return
	}

	grpcServer = grpc.NewServer()

	reflection.Register(grpcServer)

	if err := grpcServer.Serve(l); err != nil {
		log.Fatal("Failed to Server Command", err)
	}
}

func StopCmdService()  {
	grpcServer.Stop()
	log.Println("Cmd Server Closed")
}