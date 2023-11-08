package config

import "flag"

// CertCrtPath - path to crt file for TLS
var CertCrtPath string

// ServerAddress - Gophkeeper server address
var ServerAddress string

// Init - parse flags, client config init
func Init() {
	flag.StringVar(&CertCrtPath, "crt", "localhost.crt", "Path to crt-file for TLS")
	flag.StringVar(&ServerAddress, "a", "localhost:8400", "Server address")
	flag.Parse()
}
