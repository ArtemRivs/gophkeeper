package handlers

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	pb "github.com/ArtemRivs/gophkeeper/internal/pkg/proto"
	"github.com/google/uuid"

	"github.com/ArtemRivs/gophkeeper/internal/server/config"
	"github.com/ArtemRivs/gophkeeper/internal/server/storage"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
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

func Encrypt(data []byte, nonce []byte) ([]byte, error) {
	f, err := os.OpenFile(config.CipherKeyPath, os.O_RDONLY, 0777)
	if err != nil {
		return []byte{}, fmt.Errorf("unable to open file: %w", err)
	}
	defer f.Close()
	reader := bufio.NewReader(f)
	key := make([]byte, aes.BlockSize*2)
	_, err = reader.Read(key)
	if err != nil {
		return []byte{}, fmt.Errorf("unable to read from file: %w", err)
	}
	aesblock, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, fmt.Errorf("unable to create new cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(aesblock)
	if err != nil {
		return []byte{}, fmt.Errorf("unable to create new GCM: %w", err)
	}
	Log.Debug().Msgf("Encrypt Nonce %v, data %v", nonce[:aesgcm.NonceSize()], data)
	dst := aesgcm.Seal(nil, nonce[:aesgcm.NonceSize()], data, nil)
	Log.Debug().Msgf("encrypted: %x", dst)
	return dst, nil
}

func Decrypt(data []byte, nonce []byte) ([]byte, error) {
	f, err := os.OpenFile(config.CipherKeyPath, os.O_RDONLY, 0777)
	if err != nil {
		return []byte{}, fmt.Errorf("unable to open file: %w", err)
	}
	defer f.Close()
	reader := bufio.NewReader(f)
	key := make([]byte, aes.BlockSize*2)
	_, err = reader.Read(key)
	if err != nil {
		return []byte{}, fmt.Errorf("unable to read from file: %w", err)
	}
	aesblock, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, fmt.Errorf("unable to create new cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(aesblock)
	if err != nil {
		return []byte{}, fmt.Errorf("cunable to create new GCM: %w", err)
	}
	Log.Debug().Msgf("Decrypt Nonce %v, data %v", nonce[:aesgcm.NonceSize()], data)

	src2, err := aesgcm.Open(nil, nonce[:aesgcm.NonceSize()], data, nil)
	if err != nil {
		return []byte{}, fmt.Errorf("unable to decrypt data: %w", err)
	}
	Log.Debug().Msgf("decrypted: %v", src2)
	return src2, nil
}
func (s *Server) GetLoginPassword(ctx context.Context, in *pb.Key) (*pb.LoginPassword, error) {
	logger := zerolog.Ctx(ctx)
	logger.Info().Msg("GetLoginPassword request")
	if md, ok := metadata.FromIncomingContext(ctx); !ok {
		logger.Error().Msg("Can't get metadata from request context")
		return &pb.LoginPassword{}, status.New(codes.Internal, "Unknown error").Err()
	} else {
		clientIDValue := md.Get(ClientIDCtx)[0]
		clientId, err := uuid.Parse(clientIDValue)
		if err != nil {
			logger.Error().Err(err).Msg("Unable to parse uuid from clientID")
			return &pb.LoginPassword{}, status.New(codes.Internal, "Unable to parse client login").Err()
		}
		clientTokens := md.Get(ClientTokenCtx)
		clientToken := []byte(clientTokens[0])
		loginPassword, statusCode := s.storage.GetLoginPassword(clientId, in.Key)
		if statusCode.Code() != codes.OK {
			logger.Error().Err(statusCode.Err()).Msgf("Can't get login-password for key %v", in.Key)
			return &pb.LoginPassword{}, statusCode.Err()
		}
		loginBytes, err := hex.DecodeString(loginPassword.Login)
		if err != nil {
			logger.Error().Err(err).Msg("Unable to decode login from storage")
			return &pb.LoginPassword{}, status.New(codes.Internal, "Unable to decode login from storage").Err()
		}
		passwordBytes, err := hex.DecodeString(loginPassword.Password)
		if err != nil {
			logger.Error().Err(err).Msg("Unable to decode password from storage")
			return &pb.LoginPassword{}, status.New(codes.Internal, "Unable to decode password from storage").Err()
		}
		metaBytes, err := hex.DecodeString(loginPassword.Meta)
		if err != nil {
			logger.Error().Err(err).Msg("Unable to decode meta from storage")
			return &pb.LoginPassword{}, status.New(codes.Internal, "Unable to decode meta from storage").Err()
		}
		login, err := Decrypt(loginBytes, clientToken)
		if err != nil {
			logger.Error().Err(err).Msg("Unable to decrypt login from storage")
			return &pb.LoginPassword{}, status.New(codes.Internal, "Unable to decrypt login from storage").Err()
		}
		password, err := Decrypt(passwordBytes, clientToken)
		if err != nil {
			logger.Error().Err(err).Msg("Unable to decrypt password from storage")
			return &pb.LoginPassword{}, status.New(codes.Internal, "Unable to decrypt password from storage").Err()
		}
		meta, err := Decrypt(metaBytes, clientToken)
		if err != nil {
			logger.Error().Err(err).Msg("Unable to decrypt metadata from storage")
			return &pb.LoginPassword{}, status.New(codes.Internal, "Unable to decrypt metadata from storage").Err()
		}
		logger.Info().Msg("Request completed successfully")

		return &pb.LoginPassword{
			Login:    string(login),
			Password: string(password),
			Key:      in.Key,
			Meta:     string(meta),
		}, statusCode.Err()
	}
}

func (s *Server) UpdateLoginPassword(ctx context.Context, in *pb.LoginPassword) (*emptypb.Empty, error) {
	logger := zerolog.Ctx(ctx)
	logger.Info().Msg("UpdateLoginPassword request")
	if md, ok := metadata.FromIncomingContext(ctx); !ok {
		logger.Error().Msg("Can't get metadata from request context")
		return &emptypb.Empty{}, status.New(codes.Internal, "Unknown error").Err()
	} else {
		clientIDValue := md.Get(ClientIDCtx)[0]
		clientId, err := uuid.Parse(clientIDValue)
		if err != nil {
			logger.Error().Err(err).Msg("Unable to parse uuid from clientID")
			return &emptypb.Empty{}, status.New(codes.Internal, "Unable to parse client login").Err()
		}
		clientTokens := md.Get(ClientTokenCtx)
		clientToken := []byte(clientTokens[0])
		loginBytes := []byte(in.Login)
		passwordBytes := []byte(in.Password)
		metaBytes := []byte(in.Meta)
		login, err := Encrypt(loginBytes, clientToken)
		if err != nil {
			logger.Error().Err(err).Msg("Unable to encrypt login")
			return &emptypb.Empty{}, status.New(codes.Internal, "Unable to encrypt login").Err()
		}
		password, err := Encrypt(passwordBytes, clientToken)
		if err != nil {
			logger.Error().Err(err).Msg("Unable to encrypt password")
			return &emptypb.Empty{}, status.New(codes.Internal, "Unable to encrypt password").Err()
		}
		meta, err := Encrypt(metaBytes, clientToken)
		if err != nil {
			logger.Error().Err(err).Msg("Unable to encrypt meta")
			return &emptypb.Empty{}, status.New(codes.Internal, "Unable to encrypt meta").Err()
		}
		statusCode := s.storage.UpdateLoginPassword(
			clientId, in.Key, hex.EncodeToString(login), hex.EncodeToString(password), hex.EncodeToString(meta))
		if statusCode.Code() != codes.OK {
			logger.Error().Err(statusCode.Err()).Msg("Unable to update login-password in storage")
		} else {
			logger.Info().Msg("Request completed successfully")
		}
		return &emptypb.Empty{}, statusCode.Err()
	}
}

func (s *Server) DeleteLoginPassword(ctx context.Context, in *pb.Key) (*emptypb.Empty, error) {
	logger := zerolog.Ctx(ctx)
	logger.Info().Msg("DeleteLoginPassword request")
	if md, ok := metadata.FromIncomingContext(ctx); !ok {
		logger.Error().Msg("Can't get metadata from request context")
		return &emptypb.Empty{}, status.New(codes.Internal, "Unknown error").Err()
	} else {
		clientIDValue := md.Get(ClientIDCtx)[0]
		clientId, err := uuid.Parse(clientIDValue)
		if err != nil {
			logger.Error().Err(err).Msg("Unable to parse uuid from clientID")
			return &emptypb.Empty{}, status.New(codes.Internal, "Unable to parse client login").Err()
		}
		statusCode := s.storage.DeleteLoginPassword(clientId, in.Key)
		if statusCode.Code() != codes.OK {
			logger.Error().Err(statusCode.Err()).Msg("Unable to delete login-password from storage")
		} else {
			logger.Info().Msg("Request completed successfully")
		}
		return &emptypb.Empty{}, statusCode.Err()
	}
}
