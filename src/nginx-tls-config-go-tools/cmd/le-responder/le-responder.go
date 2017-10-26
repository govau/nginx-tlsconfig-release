package main

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	yaml "gopkg.in/yaml.v2"

	"github.com/govau/cf-common/credhub"
)

type config struct {
	CredHub credhub.Client `yaml:"credhub"`
	ACME    struct {
		Key struct {
			PrivateKey string `yaml:"private_key"`
		} `yaml:"key"`
		URL               string `yaml:"url"`
		DaysBeforeToRenew int    `yaml:"days_before"`
	} `yaml:"acme"`
	Port         int `yaml:"port"`
	Certificates []struct {
		Hostnames     []string `yaml:"hostnames"`
		ChallengeType string   `yaml:"challenge"`
	} `yaml:"certificates"`
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
	err = c.CredHub.Init()
	if err != nil {
		return nil, err
	}

	return &c, nil
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
		log.Println("Started daemon")
		http.ListenAndServe(fmt.Sprintf(":%d", conf.Port), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// right back at you!
			r.Write(w)
		}))
	}
}
