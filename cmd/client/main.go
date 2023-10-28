//go:build linux || windows || darwin

package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/ArtemRivs/gophkeeper/internal/client/config"
	"github.com/ArtemRivs/gophkeeper/internal/client/console"
	"github.com/ArtemRivs/gophkeeper/internal/client/sender"
)

// Use command `go build -ldflags "-X main.Version=0.0.1 -X 'main.BuildTime=$(date +'%Y/%m/%d %H:%M:%S')'" client/main.go`
var (
	Version   string
	BuildTime string
)

func main() {
	fmt.Printf("Client version %v, buildTime %v\n", Version, BuildTime)
	config.Init()
	consoleObj := console.NewConsole()
	reqSender := sender.NewSender()
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)

	go func() {
		<-sigChan
		fmt.Println("Exit client")
		os.Exit(0)
	}()

	for {
		userLoginPass := consoleObj.Start()
		err := reqSender.Register(userLoginPass)
		fmt.Println("Sent")
		if err != nil {
			fmt.Println(err)
		} else {
			break
		}
	}
	for {
		data := consoleObj.ParseCommandCycle()
		switch data.Command {
		case "exit":
			sigChan <- syscall.SIGTERM
		}
	}
}
