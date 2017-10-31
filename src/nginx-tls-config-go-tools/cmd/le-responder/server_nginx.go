package main

import (
	"fmt"
	"net/http"
)

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
}

func (n *nginxServer) Init() error {
	return nil
}

func (n *nginxServer) RunForever() error {
	return http.ListenAndServe(fmt.Sprintf(":%d", n.Port), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("yo"))
	}))
}
