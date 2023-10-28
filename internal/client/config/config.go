package config

import "flag"

var CertCrtPath string
var ServerAddress string

func Init() {
	flag.StringVar(&CertCrtPath, "crt", "localhost.crt", "Path to crt-file for TLS")
	flag.StringVar(&ServerAddress, "a", "localhost:8400", "Server address")
	flag.Parse()
}
