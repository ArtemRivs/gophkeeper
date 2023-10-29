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

type InputData struct {
	Command  string
	DataType string
	Data     interface{}
	Key      string
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

func (console Console) ParseFilePath(token string) string {
	fmt.Printf("Enter %v file path\n", token)
	for {
		path, _ := console.reader.ReadString('\n')
		path = string(bytes.TrimRight([]byte(path), "\n"))
		if validator.CheckFileExistence(path) {
			return path
		}
		fmt.Printf("Unable to open %v file path, enter another one\n", token)
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

var validDataTypes = []string{"login_pass", "card", "text", "bytes"}

func checkInputDataTypeIsValid(inputDataType string) bool {
	for _, dataType := range validDataTypes {
		if dataType == inputDataType {
			return true
		}
	}
	return false
}

func (console Console) ParseInputDataType() string {
	fmt.Println("Select one data type: 'login_pass', 'card', 'text', 'bytes'")
	for {
		inputDataType, _ := console.reader.ReadString('\n')
		inputDataType = string(bytes.TrimRight([]byte(inputDataType), "\n"))
		if checkInputDataTypeIsValid(inputDataType) {
			return inputDataType
		}
		fmt.Println("You entered the wrong data type. Select one from 'login_pass', 'card', 'text', 'bytes'")
	}
}

func (console Console) ParseCommandCycle() InputData {
	fmt.Println("Select command from 'add', 'get', 'update', 'delete', 'exit'")
	for {
		cmd, _ := console.reader.ReadString('\n')
		cmd = string(bytes.TrimRight([]byte(cmd), "\n"))
		switch cmd {
		case "exit":
			return InputData{Command: "exit"}
		case "add":
			dataType := console.ParseInputDataType()
			data := console.TypeToFunction[dataType].(func(console Console) interface{})(console)
			return InputData{Data: data, DataType: dataType, Command: "add"}
		case "get":
			dataType := console.ParseInputDataType()
			key := console.ParseStringWithLength("Key", 3)
			return InputData{Key: key, DataType: dataType, Command: "get"}
		case "update":
			dataType := console.ParseInputDataType()
			data := console.TypeToFunction[dataType].(func(console Console) interface{})(console)
			return InputData{Data: data, DataType: dataType, Command: "update"}
		case "delete":
			dataType := console.ParseInputDataType()
			key := console.ParseStringWithLength("Key", 3)
			return InputData{Key: key, DataType: dataType, Command: "delete"}
		default:
			fmt.Println("You entered the wrong command. Select one from 'add', 'get', 'update', 'delete', 'exit'")
		}
	}

}

func (console Console) Run() interface{} {
	fmt.Printf("Successful authentification")
	return console.ParseCommandCycle()

}
