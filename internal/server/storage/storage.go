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

// Client - struct for storage add/get client data
type Client struct {
	ID           string // ID - client db id.
	Login        string // Login - client Login.
	PasswordHash string // PasswordHash - client password hash.
}

var psqlErr *pgconn.PgError // ERROR postgres package has not type or method

// IRepository - repository interface
type IRepository interface {
	GetClientByLogin(login string) (Client, *status.Status)                                                                                           // GetClientByLogin - get client data by login
	AddClient(login string, passwordHash string) *status.Status                                                                                       // AddClient - add new client data
	AddLoginPassword(clientId uuid.UUID, key string, login string, password string, meta string) *status.Status                                       // AddLoginPassword - add new login password data
	GetLoginPassword(clientId uuid.UUID, key string) (console.LoginPass, *status.Status)                                                              // GetLoginPassword - get existing login password data
	UpdateLoginPassword(clientId uuid.UUID, key string, login string, password string, meta string) *status.Status                                    // UpdateLoginPassword - update existing login password data
	DeleteLoginPassword(clientId uuid.UUID, key string) *status.Status                                                                                // DeleteLoginPassword - delete existing login password data
	AddText(clientId uuid.UUID, key string, path string, meta string) *status.Status                                                                  // AddText - add text data
	GetText(clientId uuid.UUID, key string) (console.Text, *status.Status)                                                                            // GetText - get text data
	UpdateText(clientId uuid.UUID, key string, filename string, meta string) *status.Status                                                           // UpdateText - update text data
	DeleteText(clientId uuid.UUID, key string) *status.Status                                                                                         // DeleteText - delete text data
	AddBinary(clientId uuid.UUID, key string, path string, meta string) *status.Status                                                                // AddBinary - add binary data
	GetBinary(clientId uuid.UUID, key string) (console.Bytes, *status.Status)                                                                         // GetBinary - get binary data
	UpdateBinary(clientId uuid.UUID, key string, filename string, meta string) *status.Status                                                         // UpdateBinary - update binary data
	DeleteBinary(clientId uuid.UUID, key string) *status.Status                                                                                       // DeleteBinary - delete binary data
	AddCard(clientId uuid.UUID, key string, number string, name string, surname string, expiration string, cvv string, meta string) *status.Status    // AddCard - add card data
	UpdateCard(clientId uuid.UUID, key string, number string, name string, surname string, expiration string, cvv string, meta string) *status.Status // UpdateCard - update card data
	GetCard(clientId uuid.UUID, key string) (console.Card, *status.Status)                                                                            // GetCard - get card data
	DeleteCard(clientId uuid.UUID, key string) *status.Status                                                                                         // DeleteCard - delete card data
	Shutdown() error                                                                                                                                  // Shutdown - shutdown repository
}

// Repository - struct with db object
type Repository struct {
	db *sql.DB
}

// New - create new repository
func New(dbDSN string) IRepository {
	db, err := sql.Open("pgx", dbDSN)
	if err != nil {
		log.Printf("Error while starting db %s", err.Error())
		return nil
	}
	return &Repository{db}
}

// Shutdown - shutdown repository
func (repo *Repository) Shutdown() error {
	return repo.db.Close()
}

// GetClientByLogin - get client data by login
func (repo *Repository) GetClientByLogin(login string) (Client, *status.Status) {
	row := repo.db.QueryRow("SELECT id, password_hash FROM client WHERE login = $1", login)
	client := Client{Login: login}
	if err := row.Scan(&client.ID, &client.PasswordHash); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			fmt.Printf("No data for client login = %v", login)
			return Client{}, status.New(codes.NotFound, "This client login was not found in the database.")
		}
		log.Printf("Error while get client by login: %s", err)
		return Client{}, status.New(codes.Internal, "Failed to get client value in db")
	}
	return client, status.New(codes.OK, "Client found")
}

// AddClient - add client data
func (repo *Repository) AddClient(login string, passwordHash string) *status.Status {
	row := repo.db.QueryRow("INSERT INTO client (login, password_hash) VALUES ($1, $2) RETURNING id", login, passwordHash)
	var clientID string
	if err := row.Scan(&clientID); err != nil {
		if errors.As(err, &psqlErr) {
			if psqlErr.Code == pgerrcode.UniqueViolation {
				return status.New(codes.AlreadyExists, "A client with this login already exists")
			}
		}
		log.Printf("Error: %v", err)
		return status.New(codes.Internal, "Failed to insert new client value into db")
	}
	return status.New(codes.OK, "Client added")
}

// AddLoginPassword - add new login password data
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
		log.Printf("Error: %v", err)
		return status.New(codes.Internal, "Failed to insert login_password value into db")
	}
	return status.New(codes.OK, "Value added")
}

// GetLoginPassword - get login password data
func (repo *Repository) GetLoginPassword(clientId uuid.UUID, key string) (console.LoginPass, *status.Status) {
	fmt.Println("GetLoginPassword")
	row := repo.db.QueryRow("SELECT \"login\", \"password\", meta FROM login_password WHERE user_id = $1 AND \"key\" = $2 AND deleted is false", clientId, key)
	var loginPassword console.LoginPass
	if err := row.Scan(&loginPassword.Login, &loginPassword.Password, &loginPassword.Meta); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			fmt.Printf("Got no data for login_pass key = %v", key)
			return console.LoginPass{}, status.New(codes.NotFound, "Login_pass doesn't exist for this user and key")
		}
		log.Printf("Error: %v", err)
		return console.LoginPass{}, status.New(codes.Internal, "Failed to update login_password value in db")
	}
	return loginPassword, status.New(codes.OK, "Value updated")
}

// UpdateLoginPassword - update login password data
func (repo *Repository) UpdateLoginPassword(clientId uuid.UUID, key string, login string, password string, meta string) *status.Status {
	fmt.Println("UpdateLoginPassword")
	row := repo.db.QueryRow("UPDATE login_password SET \"login\" = $1, \"password\" = $2, meta = $3 WHERE user_id = $4 AND \"key\" = $5 AND deleted is false RETURNING id", login, password, meta, clientId, key)
	var loginPasswordId string
	if err := row.Scan(&loginPasswordId); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			fmt.Printf("No data for login_pass key = %v", key)
			return status.New(codes.NotFound, "Login_pass doesn't exist for this user and key")
		}
		log.Printf("Error: %v", err)
		return status.New(codes.Internal, "Failed to update login_password value in db")
	}
	return status.New(codes.OK, "Value updated")
}

// DeleteLoginPassword - delete login password data
func (repo *Repository) DeleteLoginPassword(clientId uuid.UUID, key string) *status.Status {
	fmt.Println("DeleteLoginPassword")
	row := repo.db.QueryRow("UPDATE login_password SET deleted = true WHERE user_id = $1 AND \"key\" = $2 RETURNING id", clientId, key)
	var loginPasswordId string
	if err := row.Scan(&loginPasswordId); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			fmt.Printf("No data for login_pass key = %v", key)
			return status.New(codes.NotFound, "Login_pass doesn't exist for this user and key")
		}
		log.Printf("Error: %v", err)
		return status.New(codes.Internal, "Failed to delete login_password value into db")
	}
	return status.New(codes.OK, "Value deleted")
}

// AddText - add text data
func (repo *Repository) AddText(clientId uuid.UUID, key string, path string, meta string) *status.Status {
	fmt.Println("AddText")
	row := repo.db.QueryRow("INSERT INTO text (user_id, \"key\", \"path\", meta) VALUES ($1, $2, $3, $4) RETURNING id", clientId, key, path, meta)
	var textIdDb string
	if err := row.Scan(&textIdDb); err != nil {
		if errors.As(err, &psqlErr) {
			if psqlErr.Code == pgerrcode.UniqueViolation {
				return status.New(codes.AlreadyExists, "Text for this user and key already exists")
			}
		}
		log.Printf("Error: %v", err)
		return status.New(codes.Internal, "Unable to insert text value into db")
	}
	return status.New(codes.OK, "Value added")
}

// GetText - get text data
func (repo *Repository) GetText(clientId uuid.UUID, key string) (console.Text, *status.Status) {
	fmt.Println("GetText")
	row := repo.db.QueryRow("SELECT \"path\", meta FROM text WHERE user_id = $1 AND \"key\" = $2 AND deleted is false", clientId, key)
	text := console.Text{Key: key}
	if err := row.Scan(&text.Path, &text.Meta); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			fmt.Printf("No data for text key = %v", key)
			return console.Text{}, status.New(codes.NotFound, "Text for this user and key doesn't exist")
		}
		log.Printf("Error: %v", err)
		return text, status.New(codes.Internal, "Unable to insert text value into db")
	}
	return text, status.New(codes.OK, "Text found")
}

// UpdateText - update text data
func (repo *Repository) UpdateText(clientId uuid.UUID, key string, filename string, meta string) *status.Status {
	fmt.Println("UpdateText")
	row := repo.db.QueryRow("UPDATE text SET \"path\" = $1, meta = $2 WHERE user_id = $3 AND \"key\" = $4 AND deleted is false RETURNING id", filename, meta, clientId, key)
	var textIdDb string
	if err := row.Scan(&textIdDb); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			fmt.Printf("No data for text key = %v", key)
			return status.New(codes.NotFound, "Text for this user and key doesn't exist")
		}
		if errors.As(err, &psqlErr) {
			if psqlErr.Code == pgerrcode.ForeignKeyViolation {
				return status.New(codes.NotFound, "Text for this user and key doesn't exist")
			}
		}
		log.Printf("Error: %v", err)
		return status.New(codes.Internal, "Unable to update text value into db")
	}
	return status.New(codes.OK, "Text updated")
}

// DeleteText - delete text data
func (repo *Repository) DeleteText(clientId uuid.UUID, key string) *status.Status {
	fmt.Println("DeleteText")
	row := repo.db.QueryRow("UPDATE text SET deleted = true WHERE user_id = $1 AND \"key\" = $2 RETURNING id", clientId, key)
	var textIdDb string
	if err := row.Scan(&textIdDb); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			fmt.Printf("Got no data for text key = %v", key)
			return status.New(codes.NotFound, "Text for this user and key doesn't exist")
		}
		log.Printf("\nGot error in DeleteText %v\n", err)
		return status.New(codes.Internal, "Unable to update text value into db")
	}
	return status.New(codes.OK, "Text deleted")

}

// AddBinary - add binary data
func (repo *Repository) AddBinary(clientId uuid.UUID, key string, path string, meta string) *status.Status {
	fmt.Println("AddBinary")
	row := repo.db.QueryRow("INSERT INTO \"binary\" (user_id, \"key\", \"path\", meta) VALUES ($1, $2, $3, $4) RETURNING id", clientId, key, path, meta)
	var binaryIdDb string
	if err := row.Scan(&binaryIdDb); err != nil {
		if errors.As(err, &psqlErr) {
			if psqlErr.Code == pgerrcode.UniqueViolation {
				return status.New(codes.AlreadyExists, "Binary for this user and key already exists")
			}
		}
		log.Printf("Error: %v", err)
		return status.New(codes.Internal, "Failed to insert binary value into db")
	}
	return status.New(codes.OK, "Value added")
}

// GetBinary - get binary data
func (repo *Repository) GetBinary(clientId uuid.UUID, key string) (console.Bytes, *status.Status) {
	fmt.Println("GetBinary")
	row := repo.db.QueryRow("SELECT \"path\", meta FROM \"binary\" WHERE user_id = $1 AND \"key\" = $2 AND deleted is false", clientId, key)
	binary := console.Bytes{Key: key}
	if err := row.Scan(&binary.Path, &binary.Meta); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			fmt.Printf("Got no data for binary key = %v", key)
			return console.Bytes{}, status.New(codes.NotFound, "Binary for this user and key doesn't exist")
		}
		log.Printf("Error: %v", err)
		return binary, status.New(codes.Internal, "Failed to insert binary value into db")
	}
	return binary, status.New(codes.OK, "Binary found")
}

// UpdateBinary - update binary data
func (repo *Repository) UpdateBinary(clientId uuid.UUID, key string, filename string, meta string) *status.Status {
	fmt.Println("UpdateBinary")
	row := repo.db.QueryRow("UPDATE \"binary\" SET \"path\" = $1, meta = $2 WHERE user_id = $3 AND \"key\" = $4 AND deleted is false RETURNING id", filename, meta, clientId, key)
	var binaryIdDb string
	if err := row.Scan(&binaryIdDb); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			fmt.Printf("No data for binary key = %v", key)
			return status.New(codes.NotFound, "Binary for this user and key doesn't exist")
		}
		if errors.As(err, &psqlErr) {
			if psqlErr.Code == pgerrcode.ForeignKeyViolation {
				return status.New(codes.NotFound, "Binary value for this user and key doesn't exist")
			}
		}
		log.Printf("Error: %v", err)
		return status.New(codes.Internal, "Failed to update binary value into db")
	}
	return status.New(codes.OK, "Binary updated")
}

// DeleteBinary - delete binary data
func (repo *Repository) DeleteBinary(clientId uuid.UUID, key string) *status.Status {
	fmt.Println("DeleteBinary")
	row := repo.db.QueryRow("UPDATE \"binary\" SET deleted = true WHERE user_id = $1 AND \"key\" = $2 RETURNING id", clientId, key)
	var binaryIdDb string
	if err := row.Scan(&binaryIdDb); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			fmt.Printf("No data for binary key = %v", key)
			return status.New(codes.NotFound, "Binary for this user and key doesn't exist")
		}
		log.Printf("\nError in DeleteBinary %v\n", err)
		return status.New(codes.Internal, "Failed to update binary value into db")
	}
	return status.New(codes.OK, "Binary deleted")
}

// AddCard - add card data
func (repo *Repository) AddCard(clientId uuid.UUID, key string, number string, name string, surname string, expiration string, cvv string, meta string) *status.Status {
	fmt.Println("AddCard")
	row := repo.db.QueryRow(
		`INSERT INTO card (user_id, "key", number, "name", surname, expiration, cvv, meta) 
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
		clientId, key, number, name, surname, expiration, cvv, meta,
	)
	var cardIdDb string
	if err := row.Scan(&cardIdDb); err != nil {
		if errors.As(err, &psqlErr) {
			if psqlErr.Code == pgerrcode.UniqueViolation {
				return status.New(codes.AlreadyExists, "Card for this user and key already exists")
			}
		}
		log.Printf("Error: %v", err)
		return status.New(codes.Internal, "Unable to insert card value into db")
	}
	return status.New(codes.OK, "Card added")
}

// UpdateCard - update card data
func (repo *Repository) UpdateCard(clientId uuid.UUID, key string, number string, name string, surname string, expiration string, cvv string, meta string) *status.Status {
	fmt.Println("UpdateCard")
	row := repo.db.QueryRow(
		`UPDATE card SET "number" = $1, "name" = $2, surname = $3, expiration = $4, cvv = $5, meta = $6
            WHERE user_id = $7 AND "key" = $8 AND deleted is false RETURNING id`,
		number, name, surname, expiration, cvv, meta, clientId, key,
	)
	var cardId string
	if err := row.Scan(&cardId); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			fmt.Printf("Got no data for card key = %v", key)
			return status.New(codes.NotFound, "Card for this user and key doesn't exist")
		}
		if errors.As(err, &psqlErr) {
			if psqlErr.Code == pgerrcode.ForeignKeyViolation {
				return status.New(codes.NotFound, "Card for this user and key doesn't exist")
			}
		}
		log.Printf("Error: %v", err)
		return status.New(codes.Internal, "Unable to update card value into db")
	}
	return status.New(codes.OK, "Card updated")
}

// GetCard - get card data
func (repo *Repository) GetCard(clientId uuid.UUID, key string) (console.Card, *status.Status) {
	fmt.Println("GetCard")
	row := repo.db.QueryRow(
		`SELECT "number", "name", surname, expiration, cvv, meta FROM card 
            WHERE user_id = $1 AND "key" = $2 and deleted is false`, clientId, key,
	)
	var card console.Card
	if err := row.Scan(&card.Number, &card.Name, &card.Surname, &card.Expiration, &card.Cvv, &card.Meta); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			fmt.Printf("Got no data for card key = %v", key)
			return console.Card{}, status.New(codes.NotFound, "Card for this user and key doesn't exist")
		}
		log.Printf("Error: %v", err)
		return console.Card{}, status.New(codes.Internal, "Unable to update card value into db")
	}
	return card, status.New(codes.OK, "Card updated")
}

// DeleteCard - delete card data
func (repo *Repository) DeleteCard(clientId uuid.UUID, key string) *status.Status {
	fmt.Println("DeleteCard")
	row := repo.db.QueryRow("UPDATE card SET deleted = true WHERE user_id = $1 AND \"key\" = $2 RETURNING id", clientId, key)
	var cardId string
	if err := row.Scan(&cardId); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			fmt.Printf("Got no data for card key = %v", key)
			return status.New(codes.NotFound, "Card for this user and key doesn't exist")
		}
		log.Printf("Error: %v", err)
		return status.New(codes.Internal, "Unable to delete card value into db")
	}
	return status.New(codes.OK, "Card deleted")
}
