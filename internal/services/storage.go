package services

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gofrs/uuid"
)

// S3 connection config
type S3Config struct {
	Bucket    string
	Endpoint  string
	AccessKey string
	SecretKey string
}

// UploadSBOMJSON uploads SBOM to S3. If S3 is unavailable or doesn't have configurations,
// fallback to saving SBOM into database
// Returns URL on S3 or DB identifier
func UploadSBOMJSON(ctx context.Context, db *sql.DB, projectID int, projectName, manifestName string, sbomJSON []byte, summaryJSON []byte) (string, error) {
	filename := fmt.Sprintf("sbom/%s.json", projectName)
	objectURL := ""

	// If S3_BUCKET isn't set, fallback to writing into DB
	if os.Getenv("S3_BUCKET") != "" {
		// Load AWS SDK v2 config
		awsCfg, err := config.LoadDefaultConfig(ctx,
			config.WithRegion("us-east-2"),
			config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
				os.Getenv("S3_ACCESS_KEY"),
				os.Getenv("S3_SECRET_KEY"),
				"",
			)),
		)

		if err == nil {
			// If a custom endpoint is available (e.g MinIO)
			if ep := os.Getenv("S3_ENDPOINT"); ep != "" {
				awsCfg.EndpointResolverWithOptions = aws.EndpointResolverWithOptionsFunc(
					func(service, region string, options ...interface{}) (aws.Endpoint, error) {
						return aws.Endpoint{
							URL:           ep,
							SigningRegion: awsCfg.Region,
						}, nil
					})
			}

			// Initialize S3 client
			s3Client := s3.NewFromConfig(awsCfg)

			//Upload SBOM to S3
			_, err = s3Client.PutObject(ctx, &s3.PutObjectInput{
				Bucket:      aws.String(os.Getenv("S3_BUCKET")),
				Key:         aws.String(filename),
				Body:        bytes.NewReader(sbomJSON),
				ContentType: aws.String("application/json"),
			})
			if err == nil {
				// Upload successful, save object URL
				objectURL = fmt.Sprintf("https://%s.s3.amazonaws.com/%s", os.Getenv("S3_BUCKET"), filename)
			}
		}
	}

	// Save SBOM to DB (fallback or with URL if S3 upload is successful)
	id, _ := uuid.NewV4()
	source := "db"
	if objectURL != "" {
		source = "s3"
	}

	_, err := db.ExecContext(ctx, `
		INSERT INTO sboms (
			id, project_id, project_name, manifest_name, source, sbom, summary, object_url
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
	`, id, projectID, projectName, manifestName, source, sbomJSON, summaryJSON, objectURL)
	if err != nil {
		return "", fmt.Errorf("failed to save SBOM to DB: %w", err)
	}

	if objectURL != "" {
		return objectURL, nil
	}
	// Return DB id if S3 is unavailable
	return fmt.Sprintf("db://%s", id.String()), nil

}
