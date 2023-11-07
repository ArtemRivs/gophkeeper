package handlers

import (
	"context"
	"errors"
	"log"
	"net"
	"testing"

	pb "github.com/ArtemRivs/gophkeeper/internal/pkg/proto"
	"github.com/ArtemRivs/gophkeeper/internal/server/mocks"
	"github.com/ArtemRivs/gophkeeper/internal/server/storage"
	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func getServer(ctx context.Context, storageImpl storage.IRepository) (pb.GophKeeperClient, func()) {
	listener := bufconn.Listen(1024 * 1024)
	baseServer := grpc.NewServer()
	pb.RegisterGophKeeperServer(baseServer, NewServer(storageImpl))
	go func() {
		if err := baseServer.Serve(listener); err != nil {
			log.Fatal(err)
		}
	}()

	conn, err := grpc.DialContext(ctx, "", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return listener.Dial()
	}), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatal(err)
	}
	closer := func() {
		err := listener.Close()
		if err != nil {
			log.Printf("error closing listener: %v", err)
		}
		baseServer.Stop()
	}

	client := pb.NewGophKeeperClient(conn)
	return client, closer
}

func TestServer_Register(t *testing.T) {
	tests := []struct {
		name         string
		clientLogin  string
		password     string
		passwordHash string
		want         *pb.LoginResult
		wantErr      error
		storageErr   *status.Status
	}{
		{
			name:         "Successful",
			clientLogin:  "AAAA",
			password:     "BBB",
			passwordHash: "e5c188acf6738314d6ff194b6b9fd2ae02f41f65807f6a603f92ddb03242ae66",
			want:         &pb.LoginResult{Token: "e5c188acf6738314d6ff194b6b9fd2ae02f41f65807f6a603f92ddb03242ae66"},
			wantErr:      nil,
			storageErr:   status.New(codes.OK, "Client added"),
		},
		{
			name:         "AlreadyExists",
			clientLogin:  "AAAA",
			password:     "BBB",
			passwordHash: "e5c188acf6738314d6ff194b6b9fd2ae02f41f65807f6a603f92ddb03242ae66",
			want:         &pb.LoginResult{},
			wantErr:      status.New(codes.AlreadyExists, "Client with this login already exists").Err(),
			storageErr:   status.New(codes.AlreadyExists, "Client with this login already exists"),
		},
		{
			name:         "Internal error",
			clientLogin:  "AAAA",
			password:     "BBB",
			passwordHash: "e5c188acf6738314d6ff194b6b9fd2ae02f41f65807f6a603f92ddb03242ae66",
			want:         &pb.LoginResult{},
			wantErr:      status.New(codes.Internal, "Unable to insert new client value into db").Err(),
			storageErr:   status.New(codes.Internal, "Unable to insert new client value into db"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			storageMock := mocks.NewMockIRepository(ctrl)
			storageMock.EXPECT().AddClient(tt.clientLogin, tt.passwordHash).Return(tt.storageErr)
			ctx := context.Background()
			client, closer := getServer(ctx, storageMock)
			defer closer()
			got, err := client.Register(ctx, &pb.UserData{Login: tt.clientLogin, Password: tt.password})

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("Register() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
			if err != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("Register() error = %v, wantErr %v", err, tt.wantErr)
				}
			}

			if (tt.want != nil) && (got != nil) && got.Token != tt.want.Token {
				t.Errorf("Register() return value = %v, want %v", got.Token, tt.want.Token)
			}
		})
	}
}

func TestServer_Login(t *testing.T) {
	tests := []struct {
		name         string
		clientLogin  string
		clientID     string
		password     string
		passwordHash string
		want         *pb.LoginResult
		wantErr      error
		storageErr   *status.Status
	}{
		{
			name:         "Correct password",
			clientLogin:  "AAAA",
			clientID:     "ABCDEF",
			password:     "BBB",
			passwordHash: "e5c188acf6738314d6ff194b6b9fd2ae02f41f65807f6a603f92ddb03242ae66",
			want:         &pb.LoginResult{Token: "e5c188acf6738314d6ff194b6b9fd2ae02f41f65807f6a603f92ddb03242ae66"},
			wantErr:      nil,
			storageErr:   status.New(codes.OK, "Client found"),
		},
		{
			name:         "Wrong password",
			clientLogin:  "AAAA",
			clientID:     "ABCDEF",
			password:     "BBBC",
			passwordHash: "e5c188acf6738314d6ff194b6b9fd2ae02f41f65807f6a603f92ddb03242ae66",
			want:         &pb.LoginResult{},
			wantErr:      status.New(codes.InvalidArgument, "Incorrect password").Err(),
			storageErr:   status.New(codes.OK, "Client found"),
		},
		{
			name:         "No client in storage",
			clientLogin:  "AAAA",
			clientID:     "ABCDEF",
			password:     "BBBC",
			passwordHash: "e5c188acf6738314d6ff194b6b9fd2ae02f41f65807f6a603f92ddb03242ae66",
			want:         &pb.LoginResult{},
			wantErr:      status.New(codes.NotFound, "Client with this login doesn't exist").Err(),
			storageErr:   status.New(codes.NotFound, "Unable to find client with this login in db"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			storageMock := mocks.NewMockIRepository(ctrl)
			storageMock.EXPECT().GetClientByLogin(tt.clientLogin).Return(storage.Client{ID: tt.clientID, Login: tt.clientLogin, PasswordHash: tt.passwordHash}, tt.storageErr)
			ctx := context.Background()
			client, closer := getServer(ctx, storageMock)
			defer closer()
			got, err := client.Login(ctx, &pb.UserData{Login: tt.clientLogin, Password: tt.password})
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("AddLoginPassword() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
			if err != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("AddLoginPassword() error = %v, wantErr %v", err, tt.wantErr)
				}
			}

			if (tt.want != nil) && (got != nil) && got.Token != tt.want.Token {
				t.Errorf("AddLoginPassword() return value = %v, want %v", got.Token, tt.want.Token)
			}
		})
	}
}

func TestServer_AddLoginPassword(t *testing.T) {
	tests := []struct {
		name         string
		clientLogin  string
		clientID     string
		passwordHash string
		login        string
		password     string
		key          string
		meta         string
		want         *pb.LoginResult
		wantErr      error
		storageErr   *status.Status
	}{
		{
			name:         "Correct password",
			clientLogin:  "AAAA",
			clientID:     "ABCDEF",
			passwordHash: "e5c188acf6738314d6ff194b6b9fd2ae02f41f65807f6a603f92ddb03242ae66",
			password:     "BBB",
			login:        "New_login",
			key:          "New_key",
			meta:         "meta",
			want:         &pb.LoginResult{Token: "e5c188acf6738314d6ff194b6b9fd2ae02f41f65807f6a603f92ddb03242ae66"},
			wantErr:      nil,
			storageErr:   status.New(codes.OK, "Value added"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			storageMock := mocks.NewMockIRepository(ctrl)
			storageMock.EXPECT().GetClientByLogin(tt.clientLogin).Return(storage.Client{ID: tt.clientID, Login: tt.clientLogin, PasswordHash: tt.passwordHash}, tt.storageErr)
			clientId, err := uuid.Parse(tt.clientID)
			if err != nil {
				t.Errorf("GetClientByLogin() error = %v", err)
			}
			storageMock.EXPECT().AddLoginPassword(clientId, tt.key, tt.login, tt.password, tt.meta).Return(tt.storageErr)
			md := metadata.New(map[string]string{})
			md.Set(ClientIDCtx, tt.clientID)
			ctx := metadata.NewIncomingContext(context.Background(), md)
			client, closer := getServer(ctx, storageMock)
			defer closer()
			_, err = client.AddLoginPassword(ctx, &pb.LoginPassword{Login: tt.login, Password: tt.password, Key: tt.key, Meta: tt.meta})
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("AddLoginPassword() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
			if err != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("AddLoginPassword() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
		})
	}
}
