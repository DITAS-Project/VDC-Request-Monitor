/*
 * Copyright 2018 Information Systems Engineering, TU Berlin, Germany
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *                       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * This is being developed for the DITAS Project: https://www.ditas-project.eu/
 */
package monitor

import (
	"io/ioutil"
	"net/http"

	"github.com/gorilla/mux"
)

func (mon *RequestMonitor) initTombstoneAPI(router *mux.Router) {
	router.HandleFunc("/tombstone", mon.activateTombstone).Methods("POST")
	router.HandleFunc("/revive", mon.deactivateTombstone).Methods("POST")
}

func (mon *RequestMonitor) activateTombstone(w http.ResponseWriter, r *http.Request) {
	if err := mon.Authenticate(r, mon.tombstoneSecret); err != nil {
		http.Error(w, "Unauthorized", 401)
		return
	} else {
		data, err := ioutil.ReadAll(r.Body)
		if err != nil {
			logger.Debugf("failed to read url in tombstone %v", err)
			http.Error(w, "Maleformed Request", http.StatusBadRequest)
			return
		}
		url := string(data)

		logger.Infof("tombstone triggered, rejecting all traffic to %s", url)
		mon.setTombstone(url)
	}
}

func (mon *RequestMonitor) deactivateTombstone(w http.ResponseWriter, r *http.Request) {
	if err := mon.Authenticate(r, mon.tombstoneSecret); err != nil {
		http.Error(w, "Unauthorized", 401)
		return
	} else {
		logger.Info("tombstone reset, accepting traffic again")
		mon.resetTombstone()
	}
}
