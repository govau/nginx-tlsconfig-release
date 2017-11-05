package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	yaml "gopkg.in/yaml.v2"
)

type config struct {
	NginxPid  string `yaml:"nginx_pid"` // path to file with nginx pid in it
	Bootstrap string `yaml:"bootstrap"` // bootstrap config so that nginx can start
	Period    int    `yaml:"period"`    // seconds between refresh attempts
	Server    struct {
		URL               string `yaml:"url"`
		ClientCertificate struct {
			PrivateKey  string `yaml:"private_key"`
			Certificate string `yaml:"certificate"`
		} `yaml:"client_certificate"`
		CACerts []string `yaml:"ca_certificates"`
	} `yaml:"server"`

	ConfigDir  string `yaml:"config_dir"` // dir to write nginx config to
	httpClient *http.Client
}

func newConf(configPath string) (*config, error) {
	if configPath == "" {
		return nil, errors.New("must specify a config path")
	}

	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	var c config
	err = yaml.Unmarshal(data, &c)
	if err != nil {
		return nil, err
	}

	_, err = os.Stat(c.ConfigDir)
	switch {
	case err == nil:
		// pass
	case os.IsNotExist(err):
		err = os.MkdirAll(c.ConfigDir, 0700)
		if err != nil {
			return nil, err
		}
	default:
		return nil, err
	}

	if c.Period == 0 {
		return nil, errors.New("you must specify a refresh period of at least 1 second")
	}

	tlsCert, err := tls.X509KeyPair([]byte(c.Server.ClientCertificate.Certificate), []byte(c.Server.ClientCertificate.PrivateKey))
	if err != nil {
		return nil, err
	}

	caCertPool := x509.NewCertPool()
	for _, ca := range c.Server.CACerts {
		ok := caCertPool.AppendCertsFromPEM([]byte(ca))
		if !ok {
			return nil, errors.New("no cert in pem")
		}
	}

	// Setup HTTPS client
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		RootCAs:      caCertPool,
	}
	tlsConfig.BuildNameToCertificate()
	c.httpClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	return &c, nil
}

func (c *config) ReloadNginx() error {
	content, err := ioutil.ReadFile(c.NginxPid)
	if err != nil {
		return err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(content)))
	if err != nil {
		return err
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return process.Signal(syscall.SIGHUP)
}

// Returns (did we write a new file)
func (c *config) SaveSafe(name string, data []byte) (bool, error) {
	if name == "nginx.conf" {
		data = []byte(strings.Replace(string(data), "{{PWD}}", c.ConfigDir, -1))
	}

	fpath := filepath.Join(c.ConfigDir, name)

	// See if we can avoid...
	oldData, err := ioutil.ReadFile(fpath)
	if err == nil {
		if bytes.Equal(oldData, data) {
			return false, nil // all done here
		}
	}

	// Write to new file
	err = ioutil.WriteFile(fpath+".new", data, 0400)
	if err != nil {
		return false, err
	}

	// Rename over old file, which is meant to be somewhat "atomic" sometimes...
	err = os.Rename(fpath+".new", fpath)
	if err != nil {
		return false, err
	}

	return true, nil
}

func (c *config) handleNoFailBootup(err error) (bool, error) {
	log.Println("error connecting to server, but since it's startup time, we'll fail gracefully. Error that we're ignoring is:", err)

	_, err = os.Stat(filepath.Join(c.ConfigDir, "nginx.conf"))
	if err != nil {
		log.Println("nginx.conf not found, we'll overwrite with bootstrap config")
		return c.SaveSafe("nginx.conf", []byte(c.Bootstrap))
	}

	log.Println("nginx.conf found, we'll do nothing")
	return false, nil

}

func (c *config) tryUpdate() (bool, error) {
	resp, err := c.httpClient.Get(c.Server.URL)
	if err != nil {
		return false, err
	}

	if resp.StatusCode != http.StatusOK {
		return false, errors.New("bad status code from server")
	}

	defer resp.Body.Close()

	gzipReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		return false, err
	}

	tarReader := tar.NewReader(gzipReader)
	retDirty := false
	for {
		header, err := tarReader.Next()
		switch {
		case err == io.EOF:
			return retDirty, nil

		case err != nil:
			return false, err

		case header != nil && header.Typeflag == tar.TypeReg:
			data := make([]byte, header.Size)
			_, err := tarReader.Read(data)
			if err != nil {
				return false, err
			}
			dirty, err := c.SaveSafe(header.Name, data)
			if err != nil {
				return false, err
			}
			if dirty {
				retDirty = true
			}
		}
	}
}

func (c *config) UpdateConfig(failEmpty bool) (bool, error) {
	dirty, err := c.tryUpdate()
	if err != nil {
		if failEmpty {
			return c.handleNoFailBootup(err)
		}
		return false, err
	}
	return dirty, nil
}

func main() {
	var configPath string
	var daemon bool

	flag.StringVar(&configPath, "config", "", "Path to config file - required")
	flag.BoolVar(&daemon, "daemon", false, "If set, run as a daemon, and reload pid each time")
	flag.Parse()

	conf, err := newConf(configPath)
	if err != nil {
		log.Fatal("error parsing config file", err)
	}

	if daemon {
		for {
			log.Println("Updating config")
			dirty, err := conf.UpdateConfig(false)
			if err == nil {
				if dirty { // only reload if we actually changed a file on disk, and fully succeeded
					err = conf.ReloadNginx()
				}
			}
			if err != nil {
				log.Println("Error updating config, will keep previous config and ignore error:", err)
			}
			time.Sleep(time.Duration(conf.Period) * time.Second)
		}
	} else {
		// once off, just update
		_, err = conf.UpdateConfig(true)
		if err != nil {
			// this is usually ignored by the calling script
			log.Fatal("error updating config:", err)
		}
	}
}
