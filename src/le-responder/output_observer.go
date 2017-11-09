package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
)

type certObserver interface {
	CertsAreUpdated(certs []*credhubCert) error
}

type bucket struct {
	Region       string `yaml:"region"`
	Bucket       string `yaml:"bucket"`
	Object       string `yaml:"object"`
	AccessKey    string `yaml:"access_key"`
	AccessSecret string `yaml:"access_secret"`

	awsMutex   sync.Mutex
	awsSession *session.Session

	lastSuccessfulWritten []byte
}

func stringval(s *string) string {
	if s == nil {
		return "n/a"
	}
	return *s
}

func (b *bucket) Put(data []byte) error {
	b.awsMutex.Lock()
	defer b.awsMutex.Unlock()

	if bytes.Equal(data, b.lastSuccessfulWritten) {
		return nil
	}

	if b.awsSession == nil {
		sess, err := session.NewSession(&aws.Config{
			Region:      aws.String(b.Region),
			Credentials: credentials.NewStaticCredentials(b.AccessKey, b.AccessSecret, ""),
		})
		if err != nil {
			return err
		}
		b.awsSession = sess
	}

	result, err := s3manager.NewUploader(b.awsSession).Upload(&s3manager.UploadInput{
		Bucket: aws.String(b.Bucket),
		Key:    aws.String(b.Object),
		Body:   bytes.NewReader(data),
	})
	if err != nil {
		return err
	}

	b.lastSuccessfulWritten = data

	log.Printf("Cert tarball successfully uploaded to: %s (version %s)\n", result.Location, stringval(result.VersionID))

	return nil
}

type outputObserver struct {
	S3 []*bucket `yaml:"s3"`
}

func (n *outputObserver) createTarball(certs []*credhubCert) ([]byte, error) {
	buffer := &bytes.Buffer{}
	gzipWriter := gzip.NewWriter(buffer)
	tarWriter := tar.NewWriter(gzipWriter)

	for _, cert := range certs {
		hn := hostFromPath(cert.path)
		he := hex.EncodeToString([]byte(hn))

		certBytes := []byte(fmt.Sprintf("%s\n%s\n", strings.TrimSpace(cert.PrivateKey), strings.TrimSpace(cert.Certificate)))

		err := tarWriter.WriteHeader(&tar.Header{
			Name:     he + ".crt",
			Mode:     0600,
			Size:     int64(len(certBytes)),
			Typeflag: tar.TypeReg,
		})
		if err != nil {
			return nil, err
		}
		_, err = tarWriter.Write(certBytes)
		if err != nil {
			return nil, err
		}
	}

	err := tarWriter.Close()
	if err != nil {
		return nil, err
	}
	err = gzipWriter.Close()
	if err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

func (n *outputObserver) CertsAreUpdated(certs []*credhubCert) error {
	tb, err := n.createTarball(certs)
	if err != nil {
		return err
	}

	for _, bucket := range n.S3 {
		err = bucket.Put(tb)
		if err != nil {
			return err
		}
	}

	return nil
}
