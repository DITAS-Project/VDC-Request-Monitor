package monitor

import (
	"fmt"
	"github.com/gbrlsnchs/jwt/v3"
	"github.com/gorilla/mux"
	"net/http"
)

func (mon *RequestMonitor) initExchangeAPI(router *mux.Router) {
	router.HandleFunc("/messages", mon.collectRawMessages).Methods("GET")
}

func (mon *RequestMonitor) collectRawMessages(w http.ResponseWriter, r *http.Request) {
	if mon.conf.ForwardTraffic {
		if err := mon.Authenticate(r); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Header().Add("Content-Type", "application/json")
		_, err := w.Write(mon.exporter.Dump())
		if err != nil {
			log.Infof("failed to send exchange messages %+v", err)
		}

	} else {
		http.Error(w, "Function is Deactivated", http.StatusNoContent)
	}
}

func (mon *RequestMonitor) Authenticate(req *http.Request) error {
	token := req.Header.Get("Authorization")
	if token != "" && len(token) > len("Bearer")+1 {
		token = token[len("Bearer")+1:]
		var payload jwt.Payload
		_, err := jwt.Verify([]byte(token), mon.exchangeSecret, &payload)
		if err != nil {
			return fmt.Errorf("could not validate token %+v", err)
		}
		return nil
	}
	return fmt.Errorf("no auth header set")
}
