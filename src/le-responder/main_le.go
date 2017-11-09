package main

//go:generate go-bindata -o static.go data/

import (
	"flag"
	"log"
)

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
		conf.RunForever()
	}
}
