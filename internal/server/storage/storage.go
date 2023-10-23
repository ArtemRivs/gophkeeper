package storage

import (
	"database/sql"
	"errors"
	"fmt"
	"log"

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
