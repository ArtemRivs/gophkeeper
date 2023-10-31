package config

import "flag"

// CertCrtPath - path to crt file for TLS
var CertCrtPath string

// CertKeyPath - path to key file for TLS
var CertKeyPath string

// DatabaseDSN - database connection address
var DatabaseDSN string

// ServerAddress - address for running server
var ServerAddress string

// CipherKeyPath - path to cipher key
var CipherKeyPath string

// LogPath - path to log file
var LogPath string

// Init - parse flags
func Init() {
	flag.StringVar(&CertCrtPath, "crt", "localhost.crt", "Path to crt file for TLS")
	flag.StringVar(&CertKeyPath, "key", "localhost.key", "Path to key file for TLS")
	flag.StringVar(&DatabaseDSN, "d", "postgresql://GKAdmin:GKPass@localhost:6432/gophkeeper?sslmode=disable", "Database connection address")
	flag.StringVar(&ServerAddress, "a", "localhost:8400", "Server address")
	flag.StringVar(&CipherKeyPath, "c", "cipher_key.txt", "Cipher key path")
	flag.StringVar(&LogPath, "l", "logs/gophkeeper.log", "Server log path")
	flag.Parse()
}
