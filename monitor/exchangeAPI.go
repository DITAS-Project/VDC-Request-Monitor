package monitor

import (
	"net/http"

	"github.com/gorilla/mux"
)

func (mon *RequestMonitor) initExchangeAPI(router *mux.Router) {
	router.HandleFunc("/messages", mon.collectRawMessages).Methods("GET")
}

func (mon *RequestMonitor) collectRawMessages(w http.ResponseWriter, r *http.Request) {
	if mon.conf.ForwardTraffic {
		if err := mon.Authenticate(r, mon.exchangeSecret); err != nil {
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
