package main

import (
	"fmt"
	"log"
	"net/http"
	"sync"
)

type serverResponder struct {
	Port int `yaml:"port"`

	challengeMutex    sync.RWMutex
	challengeResponse map[string][]byte
}

func (sr *serverResponder) Init() error {
	sr.challengeResponse = make(map[string][]byte)
	return nil
}

func (sr *serverResponder) SetChallengeValue(k string, v []byte) error {
	sr.challengeMutex.Lock()
	sr.challengeResponse[k] = v
	sr.challengeMutex.Unlock()
	return nil
}

func (sr *serverResponder) ClearChallengeValue(k string) {
	sr.challengeMutex.Lock()
	delete(sr.challengeResponse, k)
	sr.challengeMutex.Unlock()
}

func (sr *serverResponder) RunForever() {
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", sr.Port), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sr.challengeMutex.RLock()
		v, ok := sr.challengeResponse[r.URL.Path]
		sr.challengeMutex.RUnlock()
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Write(v)
	})))
}
