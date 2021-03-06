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
//DEPRECATED
package monitor

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
)

type ExchangeAgent interface {
	Start()
	Stop()
	Add(ExchangeMessage)
	Dump() []byte
}

type ExchangeReporter struct {
	Queue            chan ExchangeMessage
	ExchangeEndpoint string
	QuitChan         chan bool
}

//NewExchangeReporter creates a new exchange worker
func NewExchangeReporter(ExchangeEndpoint string) (*ExchangeReporter, error) {
	//Wait for endpoint to become availible or timeout with error
	return &ExchangeReporter{
		Queue:            make(chan ExchangeMessage, 10),
		ExchangeEndpoint: ExchangeEndpoint,
		QuitChan:         make(chan bool),
	}, nil
}

func (er *ExchangeReporter) Add(message ExchangeMessage) {
	er.Queue <- message
}

func (er *ExchangeReporter) Dump() []byte {
	return nil
}

//Start will create a new worker process, for processing exchange Messages
func (er *ExchangeReporter) Start() {
	go func() {
		for {

			select {
			case work := <-er.Queue:
				b := new(bytes.Buffer)
				json.NewEncoder(b).Encode(work)
				//send
				log.Debugf("sending data to exchange: %+v", er.ExchangeEndpoint)
				resp, err := http.Post(er.ExchangeEndpoint, "application/json; charset=utf-8", b)

				if err != nil {
					log.Debugf("failed to forward to :%+v", err)
					return
				}

				if resp.StatusCode > 200 {
					msg, err := ioutil.ReadAll(resp.Body)
					if err != nil {
						log.Infof("exchange failed %d - %s", resp.StatusCode, string(msg))
					}
				}
				log.Debugf("send data to excahge with: %d", resp.StatusCode)

			case <-er.QuitChan:
				// We have been asked to stop.
				log.Info("worker stopping")
				return
			}
		}
	}()
}

//Stop will terminate any running worker process
func (er *ExchangeReporter) Stop() {
	go func() {
		er.QuitChan <- true
	}()
}
