package storage

import (
	"database/sql"
	"errors"
	"fmt"
	"log"

	"github.com/ArtemRivs/gophkeeper/internal/client/console"
	"github.com/google/uuid"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Client struct {
	ID           string
	Login        string
	PasswordHash string
}

var psqlErr *pgconn.PgError

// IRepository - repository interface
type IRepository interface {
	GetClientByLogin(login string) (Client, *status.Status)
	AddClient(login string, passwordHash string) *status.Status
	AddLoginPassword(clientId uuid.UUID, key string, login string, password string, meta string) *status.Status
	GetLoginPassword(clientId uuid.UUID, key string) (console.LoginPass, *status.Status)                           // GetLoginPassword - get existing login password data
	UpdateLoginPassword(clientId uuid.UUID, key string, login string, password string, meta string) *status.Status // UpdateLoginPassword - update existing login password data
	DeleteLoginPassword(clientId uuid.UUID, key string) *status.Status                                             // DeleteLoginPassword - delete existing login password data
	Shutdown() error
}

type Repository struct {
	db *sql.DB
}

func New(dbDSN string) IRepository {
	db, err := sql.Open("pgx", dbDSN)
	if err != nil {
		log.Printf("Error while starting db %s", err.Error())
		return nil
	}
	return &Repository{db}
}

func (repo *Repository) Shutdown() error {
	return repo.db.Close()
}

func (repo *Repository) GetClientByLogin(login string) (Client, *status.Status) {
	row := repo.db.QueryRow("SELECT id, password_hash FROM client WHERE login = $1", login)
	client := Client{Login: login}
	if err := row.Scan(&client.ID, &client.PasswordHash); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			fmt.Printf("No data for client login = %v", login)
			return Client{}, status.New(codes.NotFound, "This client login was not found in the database.")
		}
		return Client{}, status.New(codes.Internal, "Failed to get client value in db")
	}
	return client, status.New(codes.OK, "Client found")
}

func (repo *Repository) AddClient(login string, passwordHash string) *status.Status {
	row := repo.db.QueryRow("INSERT INTO client (login, password_hash) VALUES ($1, $2) RETURNING id", login, passwordHash)
	var clientID string
	if err := row.Scan(&clientID); err != nil {
		if errors.As(err, &psqlErr) {
			if psqlErr.Code == pgerrcode.UniqueViolation {
				return status.New(codes.AlreadyExists, "A client with this login already exists")
			}
		}
		return status.New(codes.Internal, "Failed to insert new client value into db")
	}
	return status.New(codes.OK, "Client added")
}

func (repo *Repository) AddLoginPassword(clientId uuid.UUID, key string, login string, password string, meta string) *status.Status {
	fmt.Println("AddLoginPassword")
	row := repo.db.QueryRow("INSERT INTO login_password (user_id, \"key\", \"login\", \"password\", meta) VALUES ($1, $2, $3, $4, $5) RETURNING id", clientId, key, login, password, meta)
	var passwordIdDb string
	if err := row.Scan(&passwordIdDb); err != nil {
		if errors.As(err, &psqlErr) {
			if psqlErr.Code == pgerrcode.UniqueViolation {
				return status.New(codes.AlreadyExists, "The login-password pair for this user and key already exists")
			}
		}
		return status.New(codes.Internal, "Failed to insert login_password value into db")
	}
	return status.New(codes.OK, "Value added")
}

func (repo *Repository) GetLoginPassword(clientId uuid.UUID, key string) (console.LoginPass, *status.Status) {
	fmt.Println("GetLoginPassword")
	row := repo.db.QueryRow("SELECT \"login\", \"password\", meta FROM login_password WHERE user_id = $1 AND \"key\" = $2 AND deleted is false", clientId, key)
	var loginPassword console.LoginPass
	if err := row.Scan(&loginPassword.Login, &loginPassword.Password, &loginPassword.Meta); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			fmt.Printf("Got no data for login_pass key = %v", key)
			return console.LoginPass{}, status.New(codes.NotFound, "Login_pass doesn't exist for this user and key")
		}
		return console.LoginPass{}, status.New(codes.Internal, "Failed to update login_password value in db")
	}
	return loginPassword, status.New(codes.OK, "Value updated")
}

func (repo *Repository) UpdateLoginPassword(clientId uuid.UUID, key string, login string, password string, meta string) *status.Status {
	fmt.Println("UpdateLoginPassword")
	row := repo.db.QueryRow("UPDATE login_password SET \"login\" = $1, \"password\" = $2, meta = $3 WHERE user_id = $4 AND \"key\" = $5 AND deleted is false RETURNING id", login, password, meta, clientId, key)
	var loginPasswordId string
	if err := row.Scan(&loginPasswordId); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			fmt.Printf("No data for login_pass key = %v", key)
			return status.New(codes.NotFound, "Login_pass doesn't exist for this user and key")
		}
		return status.New(codes.Internal, "Failed to update login_password value in db")
	}
	return status.New(codes.OK, "Value updated")
}

func (repo *Repository) DeleteLoginPassword(clientId uuid.UUID, key string) *status.Status {
	fmt.Println("DeleteLoginPassword")
	row := repo.db.QueryRow("UPDATE login_password SET deleted = true WHERE user_id = $1 AND \"key\" = $2 RETURNING id", clientId, key)
	var loginPasswordId string
	if err := row.Scan(&loginPasswordId); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			fmt.Printf("No data for login_pass key = %v", key)
			return status.New(codes.NotFound, "Login_pass doesn't exist for this user and key")
		}
		return status.New(codes.Internal, "Failed to delete login_password value into db")
	}
	return status.New(codes.OK, "Value deleted")
}
