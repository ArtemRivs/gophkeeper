package config

import "flag"

// CertCrtPath - Path to crt file for TLS
var CertCrtPath string

// CertKeyPath - Path to key file for TLS
var CertKeyPath string

// DatabaseDSN - database connection address
var DatabaseDSN string

// ServerAddress - address for running Gophkeeper server
var ServerAddress string

// CipherKeyPath - Path to cipher key
var CipherKeyPath string

// LogPath - Path to log file
var LogPath string

// Init - parse flags
func Init() {
	flag.StringVar(&CertCrtPath, "crt", "/home/cubo/go/src/gophkeeper/cmd/localhost.crt", "Path to crt file for TLS")
	flag.StringVar(&CertKeyPath, "key", "/home/cubo/go/src/gophkeeper/cmd/localhost.key", "Path to key file for TLS")
	flag.StringVar(&DatabaseDSN, "d", "postgresql://GKAdmin:GKPass@localhost:6432/gophkeeper?sslmode=disable", "Database connection address")
	flag.StringVar(&ServerAddress, "a", "localhost:8400", "Server address")
	flag.StringVar(&CipherKeyPath, "c", "/home/cubo/go/src/gophkeeper/internal/server/handlers/cipher_key.txt", "Cipher key path")
	flag.StringVar(&LogPath, "l", "/home/cubo/go/src/gophkeeper/logs/gophkeeper.log", "Server log path")
	flag.Parse()
}
