package monitor

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"github.com/gorilla/mux"
	"io/ioutil"
	"net/http"
)

func (mon *RequestMonitor) initTombstoneAPI() {
	var router = mux.NewRouter()
	router.HandleFunc("/tombstone", mon.activateTombstone).Methods("POST")
	router.HandleFunc("/revive", mon.deactivateTombstone).Methods("POST")
	fmt.Println("Running server!")
	go func() {
		err := http.ListenAndServe(":3000", router)
		if err != nil {
			log.Errorf("encountered error in tombstone api %+v", err)
		}
	}()
}

func (mon *RequestMonitor) readAndValidateSignature(r *http.Request) (bool, []byte) {
	if mon.tombstoneKey == nil {
		return false, nil
	}
	if r.Header.Get("signature") == "" {
		return false, nil
	}

	signature, err := base64.StdEncoding.DecodeString(r.Header.Get("signature"))
	if err != nil {
		log.Debugf("failed to decode signature %+v", err)
		return false, nil
	}
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Debugf("failed read message body %+v", err)
		return false, nil
	}

	hash := sha1.Sum(body)

	err = rsa.VerifyPKCS1v15(mon.tombstoneKey, crypto.SHA1, hash[:], signature)
	if err != nil {
		return false, nil
	}

	return true, body
}

func (mon *RequestMonitor) activateTombstone(w http.ResponseWriter, r *http.Request) {
	if ok, data := mon.readAndValidateSignature(r); !ok {
		http.Error(w, "Unauthorized", 401)
		return
	} else {
		url := string(data)

		logger.Infof("tombstone triggered, rejecting all traffic to %s", url)
		mon.setTombstone(url)
	}
}

func (mon *RequestMonitor) deactivateTombstone(w http.ResponseWriter, r *http.Request) {
	if ok, _ := mon.readAndValidateSignature(r); !ok {
		http.Error(w, "Unauthorized", 401)
		return
	} else {

		logger.Info("tombstone reset, accepting traffic again")

		mon.resetTombstone()
	}
}
