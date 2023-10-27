package console

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
