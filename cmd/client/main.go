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
	Version   string // Version - client build version.
	BuildTime string // BuildTime - client build time.
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
		fmt.Println("Exit client, see you!")
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
		case "add":
			switch data.DataType {
			case "login_pass":
				err := reqSender.AddLoginPassword(data.Data.(console.LoginPass))
				if err != nil {
					fmt.Printf("An error: %v\n", err)
					continue
				}
			case "text":
				err := reqSender.AddText(data.Data.(console.Text))
				if err != nil {
					fmt.Printf("An error: %v\n", err)
					continue
				}
			case "bytes":
				err := reqSender.AddBinary(data.Data.(console.Bytes))
				if err != nil {
					fmt.Printf("An error: %v\n", err)
					continue
				}
			case "card":
				err := reqSender.AddCard(data.Data.(console.Card))
				if err != nil {
					fmt.Printf("An error: %v\n", err)
					continue
				}
			}
			fmt.Println("Success")
		case "update":
			switch data.DataType {
			case "login_pass":
				err := reqSender.UpdateLoginPassword(data.Data.(console.LoginPass))
				if err != nil {
					fmt.Printf("An error: %v\n", err)
					continue
				}
			case "text":
				err := reqSender.UpdateText(data.Data.(console.Text))
				if err != nil {
					fmt.Printf("An error: %v\n", err)
					continue
				}
			case "bytes":
				err := reqSender.UpdateBinary(data.Data.(console.Bytes))
				if err != nil {
					fmt.Printf("An error: %v\n", err)
					continue
				}
			case "card":
				err := reqSender.UpdateCard(data.Data.(console.Card))
				if err != nil {
					fmt.Printf("An error: %v\n", err)
					continue
				}
			}
			fmt.Println("Success")
		case "get":
			switch data.DataType {
			case "login_pass":
				loginPass, err := reqSender.GetLoginPassword(data.Key)
				if err != nil {
					fmt.Printf("An error: %v\n", err)
					continue
				}
				fmt.Printf("Login_pass data for key %v:\nlogin: %v\npassword: %v\nmeta: %v\n", loginPass.Key, loginPass.Login, loginPass.Password, loginPass.Meta)
			case "text":
				text, err := reqSender.GetText(data.Key)
				if err != nil {
					fmt.Printf("An error: %v\n", err)
					continue
				}
				fmt.Printf("Text in filename %v\nmeta: %v\n", text.Path, text.Meta)
			case "bytes":
				bytes, err := reqSender.GetBinary(data.Key)
				if err != nil {
					fmt.Printf("An error: %v\n", err)
					continue
				}
				fmt.Printf("Bytes in filename %v\nmeta: %v\n", bytes.Path, bytes.Meta)
			case "card":
				card, err := reqSender.GetCard(data.Key)
				if err != nil {
					fmt.Printf("An error: %v\n", err)
					continue
				}
				fmt.Printf(
					"Card number: %v\nname: %v\nsurname: %v\nexpiration_date: %v\ncvv: %v\nmeta: %v\n",
					card.Number, card.Name, card.Surname, card.Expiration, card.Cvv, card.Meta,
				)
			}
		case "delete":
			switch data.DataType {
			case "login_pass":
				err := reqSender.DeleteLoginPassword(data.Key)
				if err != nil {
					fmt.Printf("An error: %v\n", err)
					continue
				}
			case "text":
				err := reqSender.DeleteText(data.Key)
				if err != nil {
					fmt.Printf("An error: %v\n", err)
					continue
				}
			case "bytes":
				err := reqSender.DeleteBinary(data.Key)
				if err != nil {
					fmt.Printf("An error: %v\n", err)
				}
			case "card":
				err := reqSender.DeleteCard(data.Key)
				if err != nil {
					fmt.Printf("An error: %v\n", err)
					continue
				}
			}
			fmt.Println("Success")
		}
		fmt.Println("Sent")
	}
}
