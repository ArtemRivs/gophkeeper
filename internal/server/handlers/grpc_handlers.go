package handlers

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"os"

	pb "github.com/ArtemRivs/gophkeeper/internal/pkg/proto"

	"github.com/ArtemRivs/gophkeeper/internal/server/storage"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const SecretKey = "SecretKey"
const ClientIDCtx = "ClientID"
const ClientTokenCtx = "ClientToken"

var Log = zerolog.New(os.Stdout).With().Timestamp().Logger()

type Server struct {
	pb.UnimplementedGophKeeperServer
	storage storage.IRepository
}

func NewServer(storage storage.IRepository) *Server {
	return &Server{storage: storage}
}
func CreateAuthUnaryInterceptor(storage storage.IRepository) func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		var token string
		var login string
		if md, ok := metadata.FromIncomingContext(ctx); ok {
			tokenValues := md.Get("ClientToken")
			if len(tokenValues) > 0 {
				token = tokenValues[0]
			}
			clientLogin := md.Get("ClientLogin")
			if len(clientLogin) > 0 {
				login = clientLogin[0]
			}
		} else {
			Log.Error().Msg("The request is missing metadata")
			return nil, status.Error(codes.Unauthenticated, "missing token and login")
		}
		sublogger := Log.With().Str("method", info.FullMethod).Str("user_login", login).Logger()
		if len(token) == 0 && info.FullMethod != "/goph_keeper.GophKeeper/Register" && info.FullMethod != "/goph_keeper.GophKeeper/Login" {
			sublogger.Error().Msg("There is no client token in the request")
			return nil, status.Error(codes.Unauthenticated, "missing client token")
		}
		if len(login) == 0 {
			sublogger.Error().Msg("The request does not contain the client login")
			return nil, status.Error(codes.Unauthenticated, "missing client login")
		}
		client, statusCode := storage.GetClientByLogin(login)
		if statusCode.Code() == codes.NotFound && info.FullMethod != "/goph_keeper.GophKeeper/Register" {
			return handler(ctx, req)
		}
		if statusCode.Code() != codes.OK {
			sublogger.Error().Err(statusCode.Err()).Msgf("Error when retrieving client from storage: %v", statusCode.Message())
			return nil, errors.New("Error when retrieving client from storage")
		}
		if len(token) != 0 && token != client.PasswordHash {
			returnStatus := status.Error(codes.Unauthenticated, "invalid client token")
			sublogger.Error().Err(returnStatus)
			return nil, errors.New("Invalid client password")
		}
		sublogger.Debug().Msgf("Client successfully authorized")
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			sublogger.Error().Msg("An error occurred while retrieving metadata from the request context")
			return nil, errors.New("An error occurred while retrieving metadata from the request context")
		}
		md.Set(ClientIDCtx, client.ID)
		ctx = metadata.NewIncomingContext(ctx, md)
		ctx = sublogger.WithContext(ctx)
		return handler(ctx, req)
	}
}

func (s *Server) Register(ctx context.Context, in *pb.UserData) (*pb.LoginResult, error) {
	logger := zerolog.Ctx(ctx)
	logger.Info().Msg("Register request")
	passwordHash := GetHashForClient(in)
	statusCode := s.storage.AddClient(in.Login, passwordHash)
	if statusCode.Code() == codes.AlreadyExists {
		logger.Info().Msgf("A client with login %v already exists", in.Login)
		return &pb.LoginResult{}, status.New(codes.AlreadyExists, "A client with this login already exists").Err()
	}
	if statusCode.Code() != codes.OK {
		logger.Error().Err(statusCode.Err())
		return &pb.LoginResult{}, statusCode.Err()
	} else {
		logger.Info().Msgf("A client with login %v successfully registered", in.Login)
		return &pb.LoginResult{Token: passwordHash}, nil
	}
}

func (s *Server) Login(ctx context.Context, in *pb.UserData) (*pb.LoginResult, error) {
	logger := zerolog.Ctx(ctx)
	logger.Info().Msg("Login request")
	client, statusCode := s.storage.GetClientByLogin(in.Login)
	if statusCode.Code() != codes.OK {
		logger.Error().Err(statusCode.Err()).Msgf("Unable to retrieve client data from storage, error: %v", statusCode.Message())
		return &pb.LoginResult{}, status.New(codes.NotFound, "The client with this login doesn't exist").Err()
	}
	passwordHash := GetHashForClient(in)
	if passwordHash != client.PasswordHash {
		logger.Info().Msgf("An incorrect password was received for client %v", in.Login)
		return &pb.LoginResult{}, status.New(codes.InvalidArgument, "Incorrect password").Err()
	}
	logger.Info().Msgf("Client with login %v has been successfully authorized", in.Login)
	return &pb.LoginResult{Token: passwordHash}, nil
}

func GetHashForClient(in *pb.UserData) string {
	h := hmac.New(sha256.New, []byte(SecretKey))
	h.Write([]byte(in.Password))
	passwordHash := h.Sum(nil)
	return hex.EncodeToString(passwordHash)
}
