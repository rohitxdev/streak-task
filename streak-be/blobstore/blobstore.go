// Package blobstore provides a wrapper around S3 client.
package blobstore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

var (
	ErrFileEmpty = errors.New("file is empty")
)

type Store struct {
	client        *s3.Client
	presignClient *s3.PresignClient
}

func New(endpoint string, region string, accessKeyId string, accessKeySecret string) (*Store, error) {
	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithBaseEndpoint(endpoint),
		config.WithRegion(region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKeyId, accessKeySecret, "")),
	)
	if err != nil {
		return nil, fmt.Errorf("could not load default config of s3 client: %w", err)
	}

	s3Client := s3.NewFromConfig(cfg)
	client := Store{
		client:        s3Client,
		presignClient: s3.NewPresignClient(s3Client),
	}

	return &client, nil
}

type PutParams struct {
	BucketName  string
	FileName    string
	ContentType string
	ExpiresIn   time.Duration
}

// Put returns presigned URL to upload a file to S3 bucket.
func (s *Store) Put(ctx context.Context, p *PutParams) (string, error) {
	args := &s3.PutObjectInput{
		Bucket:      &p.BucketName,
		Key:         &p.FileName,
		ContentType: &p.ContentType,
	}
	req, err := s.presignClient.PresignPutObject(ctx, args, s3.WithPresignExpires(p.ExpiresIn))
	if err != nil {
		return "", err
	}
	return req.URL, err
}

type GetParams struct {
	BucketName string
	FileName   string
	ExpiresIn  time.Duration
}

// Get returns presigned URL to download a file from S3 bucket.
func (s *Store) Get(ctx context.Context, p *GetParams) (string, error) {
	args := &s3.GetObjectInput{
		Bucket: &p.BucketName,
		Key:    &p.FileName,
	}
	req, err := s.presignClient.PresignGetObject(ctx, args, s3.WithPresignExpires(p.ExpiresIn))
	if err != nil {
		return "", err
	}
	return req.URL, err
}

type DeleteParams struct {
	BucketName string
	FileName   string
	ExpiresIn  time.Duration
}

// Delete returns presigned URL to delete a file from S3 bucket.
func (s *Store) Delete(ctx context.Context, p *DeleteParams) (string, error) {
	args := &s3.DeleteObjectInput{
		Bucket: &p.BucketName,
		Key:    &p.FileName,
	}
	req, err := s.presignClient.PresignDeleteObject(ctx, args, s3.WithPresignExpires(p.ExpiresIn))
	if err != nil {
		return "", err
	}
	return req.URL, err
}

type FileMetaData struct {
	LastModified time.Time `json:"lastModified"`
	FileName     string    `json:"fileName"`
	SizeInBytes  uint64    `json:"sizeInBytes"`
}

type ListParams struct {
	BucketName string
	SubDir     string
}

// List returns a list of files in a given directory in S3 bucket.
func (s *Store) List(ctx context.Context, p *ListParams) ([]FileMetaData, error) {
	var token *string
	var files []FileMetaData
	for {
		objects, err := s.client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &p.BucketName, ContinuationToken: token, Prefix: aws.String(p.SubDir)})
		if err != nil {
			return nil, err
		}
		for _, file := range objects.Contents {
			files = append(files, FileMetaData{FileName: *file.Key, LastModified: *aws.Time(*file.LastModified), SizeInBytes: uint64(*file.Size)})
		}
		if !*objects.IsTruncated {
			break
		}
		token = objects.NextContinuationToken
	}
	return files, nil
}
