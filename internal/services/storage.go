package services

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

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

// UploadSBOMJSON uploads SBOM to S3 and returns the object URL if successful.
// If S3 is not configured or upload fails, it returns an empty string without error
// so the caller can fall back to storing SBOM data in Postgres.
func UploadSBOMJSON(ctx context.Context, orgID, projectID int, projectName, manifestName string, sbomJSON []byte) (string, error) {
	bucket := os.Getenv("S3_BUCKET")
	if bucket == "" {
		return "", nil
	}

	key := buildSBOMObjectKey(orgID, projectID, manifestName)
	awsCfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion("us-east-2"),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			os.Getenv("S3_ACCESS_KEY"),
			os.Getenv("S3_SECRET_KEY"),
			"",
		)),
	)
	if err != nil {
		return "", nil
	}

	if ep := os.Getenv("S3_ENDPOINT"); ep != "" {
		awsCfg.EndpointResolverWithOptions = aws.EndpointResolverWithOptionsFunc(
			func(service, region string, options ...interface{}) (aws.Endpoint, error) {
				return aws.Endpoint{
					URL:           ep,
					SigningRegion: awsCfg.Region,
				}, nil
			})
	}

	s3Client := s3.NewFromConfig(awsCfg)
	_, err = s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(sbomJSON),
		ContentType: aws.String("application/json"),
	})
	if err != nil {
		return "", nil
	}

	return buildSBOMObjectURL(bucket, key), nil
}

func buildSBOMObjectKey(orgID, projectID int, manifestName string) string {
	safeManifest := sanitizePathSegment(manifestName)
	return path.Join(
		"sbom",
		fmt.Sprintf("org-%d", orgID),
		fmt.Sprintf("project-%d", projectID),
		safeManifest,
		fmt.Sprintf("%d-%s.json", time.Now().UTC().UnixNano(), uuid.Must(uuid.NewV4()).String()),
	)
}

func sanitizePathSegment(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		s = "manifest"
	}
	replacer := strings.NewReplacer(
		" ", "-",
		"/", "-",
		"\\", "-",
		"..", "-",
		"..", "-",
		"__", "-",
	)
	s = replacer.Replace(s)
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') ||
			(r >= '0' && r <= '9') ||
			r == '-' || r == '_' || r == '.' {
			return r
		}
		return '-'
	}, s)
}

func buildSBOMObjectURL(bucket, key string) string {
	if publicBase := strings.TrimSpace(os.Getenv("S3_PUBLIC_URL")); publicBase != "" {
		return fmt.Sprintf("%s/%s", strings.TrimRight(publicBase, "/"), key)
	}
	if ep := strings.TrimSpace(os.Getenv("S3_ENDPOINT")); ep != "" {
		return fmt.Sprintf("%s/%s/%s", strings.TrimRight(ep, "/"), bucket, key)
	}
	return fmt.Sprintf("https://%s.s3.amazonaws.com/%s", bucket, key)
}
