package db

import (
	"context"
	"database/sql"
	_ "github.com/lib/pq"
	"log"
)

var Conn *sql.DB

func InitPostgres(dns string) {
	var err error
	Conn, err = sql.Open("postgres", dns)
	if err != nil {
		log.Fatalf("DB Connection error: %v", err)
	}
	if err = Conn.PingContext(context.Background()); err != nil {
		log.Fatalf("DB ping failed: %v", err)
	}
	log.Println("PostgreSQL connected")
}
