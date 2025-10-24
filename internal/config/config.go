package config

import (
	"log"
	"os"
	"github.com/joho/godotenv"
)

type Config struct{
	DatabaseURL string
	RedisURL string
	S3Bucket string
	S3Endpoint string
	S3AccessKey string
	S3SecretKey string
	Token string
	ApiPrefix string
}

func LoadConfig() *Config{
	_ = godotenv.Load()
	cfg := &Config{
		DatabaseURL: os.Getenv("DATABASE_URL"),
		RedisURL: os.Getenv("REDIS_URL"),
		S3Bucket:    os.Getenv("S3_BUCKET"),
		S3Endpoint:  os.Getenv("S3_ENDPOINT"),
		S3AccessKey: os.Getenv("S3_ACCESS_KEY"),
		S3SecretKey: os.Getenv("S3_SECRET_KEY"),
		Token: os.Getenv("GITHUB_TOKEN"),
		ApiPrefix:   "/api/sbom",
	}
	if cfg.DatabaseURL == ""{
		log.Fatal("DATABASE_URL missing")
	}
	return cfg
}