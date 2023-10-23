package handlers

import (
	"context"
	"os"

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
