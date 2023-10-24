package main

import (
	"context"
	"fmt"

	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	pb "github.com/ArtemRivs/gophkeeper/internal/pkg/proto"

	"github.com/ArtemRivs/gophkeeper/internal/server/config"
	"github.com/ArtemRivs/gophkeeper/internal/server/db"
	"github.com/ArtemRivs/gophkeeper/internal/server/handlers"
	"github.com/ArtemRivs/gophkeeper/internal/server/storage"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func main() {
	config.Init()
	logFile, err := os.OpenFile(config.LogPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0777)
	if err != nil {
		logFile = os.Stdout
	}
	handlers.Log = zerolog.New(logFile).With().Timestamp().Logger()
	db.RunMigrations(config.DatabaseDSN)
	newStorage := storage.New(config.DatabaseDSN)
	creds, err := credentials.NewServerTLSFromFile(config.CertCrtPath, config.CertKeyPath)
	if err != nil {
		log.Fatal(err)
	}
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)

	listener, err := net.Listen("tcp", config.ServerAddress)
	if err != nil {
		log.Fatal(err)
	}
	s := grpc.NewServer(
		grpc.Creds(creds),
		grpc.UnaryInterceptor(handlers.CreateAuthUnaryInterceptor(newStorage)),
	)
	pb.RegisterGophKeeperServer(s, handlers.NewServer(newStorage))
	fmt.Println("Gophkeeper started")

	go func() {
		<-sigChan
		_, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		s.GracefulStop()
		if err := newStorage.Shutdown(); err != nil {
			fmt.Printf("Error from storage while shutting down %v\n", err)
		}
		fmt.Println("Gophkeeper was stopped")
	}()

	if err := s.Serve(listener); err != nil {
		log.Fatal(err)
	}
}
