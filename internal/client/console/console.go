package console

import (
	"bufio"
	"bytes"
	"fmt"
	"os"

	"github.com/ArtemRivs/gophkeeper/internal/client/validator"
)

type LoginPass struct {
	Login    string
	Password string
	Meta     string
	Key      string
}

type Text struct {
	Path string
	Meta string
	Key  string
}

type Bytes struct {
	Path string
	Meta string
	Key  string
}

type Card struct {
	Number     string
	Expiration string
	Name       string
	Surname    string
	Cvv        string
	Meta       string
	Key        string
}

type UserLoginPass struct {
	Login    string
	Password string
	Command  string
}

type Console struct {
	reader         *bufio.Reader
	TypeToFunction map[string]interface{}
}

func NewConsole() Console {
	reader := bufio.NewReader(os.Stdin)
	return Console{reader: reader, TypeToFunction: map[string]interface{}{
		"login_pass": Console.ParseLoginPass,
	}}
}

func (console Console) Start() UserLoginPass {
	fmt.Println("Gophkeeper started. Enter 'sign_up' to register new user, 'sign_in' to login")
	inputCmd, _ := console.reader.ReadString('\n')
	inputCmd = string(bytes.TrimRight([]byte(inputCmd), "\n"))
	for {
		if inputCmd != "sign_up" && inputCmd != "sign_in" {
			fmt.Println("You entered the wrong command. Enter one of 'sign_up', 'sign_in'")
		} else {
			break
		}
		inputCmd, _ = console.reader.ReadString('\n')
		inputCmd = string(bytes.TrimRight([]byte(inputCmd), "\n"))
	}
	loginPass := UserLoginPass{Command: inputCmd}
	fmt.Println("Login:")
	loginPass.Login, _ = console.reader.ReadString('\n')
	loginPass.Login = string(bytes.TrimRight([]byte(loginPass.Login), "\n"))
	fmt.Println("Password:")
	loginPass.Password, _ = console.reader.ReadString('\n')
	loginPass.Password = string(bytes.TrimRight([]byte(loginPass.Password), "\n"))
	return loginPass
}

func (console Console) ParseStringWithLength(token string, length int) string {
	fmt.Printf("Enter %v\n", token)
	for {
		key, _ := console.reader.ReadString('\n')
		key = string(bytes.TrimRight([]byte(key), "\n"))
		if validator.CheckStringToken(key, length) {
			return key
		}
		fmt.Printf("%v length should be at least %v\n", token, length)
	}
}

func (console Console) ParseLoginPass() interface{} {
	loginPass := LoginPass{}
	loginPass.Key = console.ParseStringWithLength("Key", 3)
	loginPass.Login = console.ParseStringWithLength("Login", 5)
	loginPass.Password = console.ParseStringWithLength("Password", 6)
	loginPass.Meta = console.ParseStringWithLength("Meta", 0)
	return loginPass
}
