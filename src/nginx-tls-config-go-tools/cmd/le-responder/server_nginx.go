package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
)

type certObserver interface {
	CertsAreUpdated(certs []*credhubCert) error
}

type nginxServer struct {
	Port    int `yaml:"port"`
	Clients struct {
		Names   []string `yaml:"names"`
		CACerts []string `yaml:"ca_certificates"`
	} `yaml:"clients"`
	Certificate struct {
		PrivateKey  string `yaml:"private_key"`
		Certificate string `yaml:"certificate"`
	} `yaml:"certificate"`
	Template struct {
		Global    string            `yaml:"global"`
		Events    string            `yaml:"events"`
		ACME      string            `yaml:"acme"`
		HTTP      string            `yaml:"http"`
		Common    string            `yaml:"common"`
		PerServer map[string]string `yaml:"server"`
	} `yaml:"template"`
	Hostname string `yaml:"hostname"`

	cert         tls.Certificate
	clientCAPool *x509.CertPool

	bytesMutex  sync.RWMutex
	cachedBytes []byte
}

func (n *nginxServer) CertsAreUpdated(certs []*credhubCert) error {
	n.bytesMutex.Lock()
	defer n.bytesMutex.Unlock()

	ips, err := net.LookupIP(n.Hostname)
	if err != nil {
		return err
	}
	if len(ips) == 0 {
		return errors.New("cannot resolve responder")
	}
	ourIP := ips[0].String()

	buffer := &bytes.Buffer{}
	gzipWriter := gzip.NewWriter(buffer)
	tarWriter := tar.NewWriter(gzipWriter)

	var serverStanzas []string
	for _, cert := range certs {
		hn := hostFromPath(cert.path)
		he := hex.EncodeToString([]byte(hn))

		pkeyBytes := []byte(cert.PrivateKey)
		err := tarWriter.WriteHeader(&tar.Header{
			Name: he + ".key",
			Mode: 0600,
			Size: int64(len(pkeyBytes)),
		})
		if err != nil {
			return err
		}
		_, err = tarWriter.Write(pkeyBytes)
		if err != nil {
			return err
		}

		certBytes := []byte(cert.Certificate)
		err = tarWriter.WriteHeader(&tar.Header{
			Name: he + ".crt",
			Mode: 0600,
			Size: int64(len(certBytes)),
		})
		if err != nil {
			return err
		}
		_, err = tarWriter.Write(certBytes)
		if err != nil {
			return err
		}

		serverStanzas = append(serverStanzas, fmt.Sprintf(`server {
			server_name %s;
			ssl_certificate %s.crt;
			ssl_certificate_key %s.key;
			%s
			%s
		}`, hn, he, he, n.Template.Common, n.Template.PerServer[cert.Type]))
	}

	nginxConf := []byte(strings.Replace(fmt.Sprintf(`%s
		events {
			%s
		}

		http {
			server {
				# ACME first, if available
				%s

				# Then other HTTP
				%s
			}
			# Per server SSL
			%s
		}`, n.Template.Global, n.Template.Events, n.Template.ACME, n.Template.HTTP, strings.Join(serverStanzas, "\n")), "IP_ADDRESS", ourIP, -1))

	err = tarWriter.WriteHeader(&tar.Header{
		Name: "nginx.conf",
		Mode: 0600,
		Size: int64(len(nginxConf)),
	})
	if err != nil {
		return err
	}
	_, err = tarWriter.Write(nginxConf)
	if err != nil {
		return err
	}
	err = tarWriter.Close()
	if err != nil {
		return err
	}
	err = gzipWriter.Close()
	if err != nil {
		return err
	}

	n.cachedBytes = buffer.Bytes()

	return nil
}

func (n *nginxServer) Init() error {
	cert, err := tls.X509KeyPair([]byte(n.Certificate.Certificate), []byte(n.Certificate.PrivateKey))
	if err != nil {
		return err
	}

	n.cert = cert

	n.clientCAPool = x509.NewCertPool()
	for _, ca := range n.Clients.CACerts {
		ok := n.clientCAPool.AppendCertsFromPEM([]byte(ca))
		if !ok {
			return errors.New("no ca certs founds in pem")
		}
	}

	return nil
}

func (n *nginxServer) handle(w http.ResponseWriter, r *http.Request) {
	n.bytesMutex.RLock()
	defer n.bytesMutex.RUnlock()

	if len(n.cachedBytes) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	w.Write(n.cachedBytes)
}

func (n *nginxServer) RunForever() error {
	return (&http.Server{
		Addr:    fmt.Sprintf(":%d", n.Port),
		Handler: http.HandlerFunc(n.handle),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{n.cert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    n.clientCAPool,
			VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				if len(rawCerts) == 0 {
					return errors.New("no certs")
				}
				cert, err := x509.ParseCertificate(rawCerts[0])
				if err != nil {
					return err
				}
				for _, cn := range n.Clients.Names {
					if cert.Subject.CommonName == cn {
						return nil // all good
					}
				}
				return errors.New("wrong name in cert")
			},
		},
	}).ListenAndServe()
}
