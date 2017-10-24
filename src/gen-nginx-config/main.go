package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v2"
)

type config struct {
	NginxJob string `yaml:"nginx_job"` // name of nginx jobs
	Template struct {
		Global string `yaml:"global"` // added to global
		Events string `yaml:"events"` // added to events element
		HTTP   string `yaml:"http"`   // added to http element
		Server string `yaml:"server"` // added within each generated element
	} `yaml:"template"`
	Refresh struct {
		ClientCert struct {
			PrivateKey  string `yaml:"private_key"`
			Certificate string `yaml:"certificate"`
		} `yaml:"client_certificate"` // PEM cert to use to authenticate to credhub
		CredHubURL    string `yaml:"credhub_url"`            // URL to access
		CredHubCACert string `yaml:"credhub_ca_certificate"` // CA cert for credhub host
		Period        int    `yaml:"period"`                 // seconds between refresh attempts
	} `yaml:"refresh"`
	lastWritten string
	configDir   string
}

func (c *config) ConnectToCredhub() error {
	caCertPool := x509.NewCertPool()
	ok := caCertPool.AppendCertsFromPEM([]byte(c.Refresh.CredHubCACert))
	if !ok {
		return errors.New("AppendCertsFromPEM was not ok")
	}

	clientCert, err := tls.X509KeyPair([]byte(c.Refresh.ClientCert.Certificate), []byte(c.Refresh.ClientCert.PrivateKey))
	if err != nil {
		return err
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caCertPool,
	}
	tlsConfig.BuildNameToCertificate()
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: transport}

	resp, err := client.Get(c.Refresh.CredHubURL + "/api/v1/data")
	if err != nil {
		return err
	}
	contents, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("Error: %d\n%s\n", resp.StatusCode, string(contents))
		return errors.New("bad response code from credhub")
	}

	log.Printf("%s\n", string(contents))
	return nil
}

func (c *config) ReloadNginx() error {
	content, err := ioutil.ReadFile(fmt.Sprintf("/var/vcap/sys/run/%s/nginx.pid", c.NginxJob))
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

func (c *config) UpdateConfig() error {
	var perServer []string

	err := c.ConnectToCredhub()
	if err != nil {
		return err
	}

	newConfig := fmt.Sprintf(`%s
		events {
			%s
		}

		http {
			%s
			%s
		}`, c.Template.Global, c.Template.Events, c.Template.HTTP, strings.Join(perServer, "\n"))

	if newConfig == c.lastWritten {
		// TODO, if we have a new cert, we'll still need to reload later
		log.Println("No changes detected, no reload")
		return nil
	}

	err = ioutil.WriteFile(c.configDir+"/nginx.conf.new", []byte(newConfig), 0400)
	if err != nil {
		return err
	}

	// Now, rename it over the old one
	return os.Rename(c.configDir+"/nginx.conf.new", c.configDir+"/nginx.conf")
}

func main() {
	var configPath string
	var daemon bool

	flag.StringVar(&configPath, "config", "", "Path to config file - required")
	flag.BoolVar(&daemon, "daemon", false, "If set, run as a daemon, and reload pid each time")
	flag.Parse()

	if configPath == "" {
		log.Fatal("must specify a config path")
	}

	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		log.Fatal("error reading config file", err)
	}
	var conf config
	err = yaml.Unmarshal(data, &conf)
	if err != nil {
		log.Fatal("error parsing config file", err)
	}
	conf.configDir = filepath.Dir(configPath)

	if daemon {
		for {
			log.Println("Updating config")
			err = conf.UpdateConfig()
			if err == nil {
				err = conf.ReloadNginx()
			}
			if err != nil {
				log.Println("Error updating config, will keep previous config and ignore error:", err)
			}
			time.Sleep(time.Duration(conf.Refresh.Period) * time.Second)
		}
	} else {
		// once off, just update
		err = conf.UpdateConfig()
		if err != nil {
			log.Fatal("error updating config:", err)
		}
	}
}
