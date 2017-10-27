package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/govau/cf-common/credhub"

	yaml "gopkg.in/yaml.v2"
)

type config struct {
	NginxJob string `yaml:"nginx_job"` // name of nginx jobs
	Template struct {
		ResponseHost      string `yaml:"responder"`           // will be resolved and added
		Global            string `yaml:"global"`              // added to global
		Events            string `yaml:"events"`              // added to events element
		HTTP              string `yaml:"http"`                // added to http element
		ACME              string `yaml:"acme"`                // added to http element
		Server            string `yaml:"server"`              // added within each generated element
		NoTLSYet          string `yaml:"pre_server"`          // adeded if no other valid server conf exists
		AdminExtHost      string `yaml:"external_admin_host"` // external hostname for admin server
		AdminServerConfig string `yaml:"admin_server"`        // config for the admin server
	} `yaml:"template"`
	CredHub   credhub.Client `yaml:"credhub"`
	Period    int            `yaml:"period"` // seconds between refresh attempts
	configDir string
}

type oauthToken struct {
	AccessToken string `json:"access_token"`
	Expiry      int64  `json:"expires_in"`
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
	c.configDir = filepath.Dir(configPath)
	err = c.CredHub.Init()
	if err != nil {
		return nil, err
	}

	if c.Period == 0 {
		return nil, errors.New("you must specify a refresh period of at least 1 second.")
	}

	return &c, nil
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

type credhubCert struct {
	CA          string `json:"ca"`
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key"`
}

var (
	errNoDNSFound = errors.New("no dns names found in cert")
)

func (c *config) MakeConfForCert(cert *credhubCert) (bool, string, error) {
	block, _ := pem.Decode([]byte(cert.Certificate))
	if block == nil {
		return false, "", errors.New("no cert found in pem")
	}
	if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
		return false, "", errors.New("invalid cert found in pem")
	}

	pc, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, "", err
	}

	if len(pc.DNSNames) == 0 {
		return false, "", errNoDNSFound
	}

	// We'll just hash the cert content for the filename
	hc := sha256.Sum256(block.Bytes)

	rv := false

	nameOfFile := hex.EncodeToString(hc[:])
	dirty, err := c.SaveSafe(nameOfFile+".key", []byte(strings.TrimSpace(cert.PrivateKey)+"\n"))
	if err != nil {
		return false, "", err
	}
	if dirty {
		rv = true
	}
	dirty, err = c.SaveSafe(nameOfFile+".crt", []byte(strings.TrimSpace(cert.Certificate)+"\n"+strings.TrimSpace(cert.CA)+"\n"))
	if err != nil {
		return false, "", err
	}
	if dirty {
		rv = true
	}

	return rv, fmt.Sprintf(`server {
		server_name %s;
		ssl_certificate %s/%s.crt;
		ssl_certificate_key %s/%s.key;
		%s
	}`, strings.Join(pc.DNSNames, " "), c.configDir, nameOfFile, c.configDir, nameOfFile, c.Template.Server), nil

}

func (c *config) GetServerConf() (bool, []string, error) {
	// TODO - return an error if the certs returned have any overlap
	var resp struct {
		Credentials []struct {
			Name string `json:"name"`
		} `json:"credentials"`
	}
	err := c.CredHub.MakeRequest("/api/v1/data", url.Values{"path": {"/certs"}}, &resp)
	if err != nil {
		return false, nil, err
	}
	var rv []string
	retDirty := false
	for _, cred := range resp.Credentials {
		var cr struct {
			Data []struct {
				Value credhubCert `json:"value"`
			} `json:"data"`
		}
		err := c.CredHub.MakeRequest("/api/v1/data", url.Values{
			"name":    {cred.Name},
			"current": {"true"},
		}, &cr)
		if err != nil {
			return false, nil, err
		}
		for _, v := range cr.Data {
			dirty, nginxConf, err := c.MakeConfForCert(&v.Value)
			switch err {
			case nil:
				rv = append(rv, nginxConf)
			case errNoDNSFound:
				log.Println("No DNS found in cert, skipping: ", cred.Name)
			default:
				return false, nil, err
			}
			if dirty {
				retDirty = true
			}
		}
	}

	return retDirty, rv, nil
}

// Returns (did we write a new file)
func (c *config) SaveSafe(name string, data []byte) (bool, error) {
	fpath := filepath.Join(c.configDir, name)

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

func (c *config) UpdateConfig(failEmpty bool) (bool, error) {
	retDirty := false
	sslInfoValid := false

	dirty, perServer, err := c.GetServerConf()
	sslInfoValid = (err == nil)
	if err != nil {
		if failEmpty {
			err = nil
		}
		if err != nil {
			return false, err
		}
	}

	if dirty {
		retDirty = true
	}

	ips, err := net.LookupIP(c.Template.ResponseHost)
	if err != nil {
		if failEmpty {
			err = nil
		} else {
			return false, err
		}
	}

	acme, admin := "", ""
	if len(ips) == 0 {
		if !failEmpty {
			return false, errors.New("cannot resolve responder")
		}
	} else {
		acme = strings.Replace(c.Template.ACME, "IP_ADDR", ips[0].String(), 1)
		admin = strings.Replace(strings.Replace(c.Template.AdminServerConfig, "IP_ADDR", ips[0].String(), 1), "EXTERNAL_ADMIN_HOST", c.Template.AdminExtHost, 1)
	}

	// Listening for SSL is our health indicator to the load balancer,
	// so we only want to do this if we are confident our config is correct.
	// We need to listen if empty, else we won't get HTTP requests though
	sslConf := ""
	if sslInfoValid {
		sslConf += "server {\n"
		if len(perServer) == 0 {
			sslConf += c.Template.NoTLSYet + "\n"
		} else {
			sslConf += c.Template.Server + "\n"
			// TODO, add certs
		}
		sslConf += admin + "\n"
		sslConf += "}\n"
		sslConf += strings.Join(perServer, "\n")
	}

	dirty, err = c.SaveSafe("nginx.conf", []byte(fmt.Sprintf(`%s
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
		}`, c.Template.Global, c.Template.Events, acme, c.Template.HTTP, sslConf)))
	if err != nil {
		return false, err
	}

	if dirty {
		retDirty = true
	}

	return retDirty, nil
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
