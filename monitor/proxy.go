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
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/lestrrat/go-jwx/jwk"

	opentracing "github.com/opentracing/opentracing-go"
)

const tokenString = `eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ1Mm43MW1jQWRIaDBxMS12QzJYMHVYX1lmZzNjY0VtaDJxT2hObTgwSGdRIn0.eyJqdGkiOiJkZDE1MGQ5OC02ZjBkLTQ2NjctODYwNi1lMzdhYWQzYzhlYzciLCJleHAiOjE1NDc2Mzg4OTEsIm5iZiI6MCwiaWF0IjoxNTQ3NjM4NTkxLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvYXV0aC9yZWFsbXMvdmRjX2R1bW15IiwiYXVkIjoiYWNjb3VudCIsInN1YiI6IjI0OTY2NDI0LTEzMjQtNDdmMy1hNTNlLTM2ZmQzMmJiMjZlMCIsInR5cCI6IkJlYXJlciIsImF6cCI6InRlc3RfY2xpZW50IiwiYXV0aF90aW1lIjowLCJzZXNzaW9uX3N0YXRlIjoiYzk4YzUxZTUtZDc1OC00YTkyLWFlYTctNjY4MzJjZGFmOWYzIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJkb2N0b3IiXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6ImVtYWlsIHByb2ZpbGUiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsIm5hbWUiOiJKb2huIERvZSIsInByZWZlcnJlZF91c2VybmFtZSI6InRlc3RfZG9jdG9yIiwiZ2l2ZW5fbmFtZSI6IkpvaG4iLCJmYW1pbHlfbmFtZSI6IkRvZSJ9.SCbhNcyLEMNSroSSGakgjp6QDNc7Jo9cRt5Rn8-LMWLhFl_4-WqlpX27MOYj0FR_MEYpfGkOUA5YbnjdI-0ViPd94-2K_pFr9NrEv6G5numoUHUdI0aVYeQunV0sl2URYGof__eYc-Bk3b9xzA7ZecLELe7t5duDO9NHpX6nNx39XJx2Ep6Trpfd2K6t2qgz6U8Icucy8YqfbBW7gjY6X3NcR1B1PvNTHDE9kTO6fJziDWRtZ8eGY86MtzwSlZUmDWexEgH8aghPHUohXVOe_Lg30NRHDfC8ppZd8dtoRo2urZLEYUllOKaT4Dr_NCFDWxJeFt0vDF9rBW1WQd3jpg`
const jwksURL = `http://localhost:8080/auth/realms/vdc_dummy/protocol/openid-connect/certs`

func (mon *RequestMonitor) serve(w http.ResponseWriter, req *http.Request) {
	var requestID = mon.generateRequestID(req.RemoteAddr)

	var exchange exchangeMessage
	//read payload
	if mon.conf.ForwardTraffic {
		body, err := ioutil.ReadAll(req.Body)

		if err != nil {
			log.Printf("Error reading body: %v", err)
			http.Error(w, "can't read body", http.StatusBadRequest)
			return
		}

		//enact proxy request
		req.ContentLength = int64(len(body))
		req.Body = ioutil.NopCloser(bytes.NewReader(body))

		exchange = exchangeMessage{
			RequestBody:   string(body),
			RequestHeader: req.Header,
		}

	}
	method := req.URL.Path
	req.URL = mon.conf.endpointURL

	operationID := mon.extractOperationId(req.URL.Path, req.Method)

	//inject tracing header
	if mon.conf.Opentracing {
		opentracing.GlobalTracer().Inject(
			opentracing.StartSpan("VDC-Request").Context(),
			opentracing.HTTPHeaders,
			opentracing.HTTPHeadersCarrier(req.Header),
		)
	}

	//inject looging header
	req.Header.Set("X-DITAS-RequestID", requestID)
	req.Header.Set("X-DITAS-OperationID", operationID)

	//validate Token
	token, err := jwt.Parse(tokenString, GetKey)
	if err != nil {

		http.Error(w, "invalid Token", http.StatusBadRequest)
		return
	}

	claims := token.Claims.(jwt.MapClaims)
	for key, value := range claims {
		fmt.Printf("%s\t%v\n", key, value)
	}

	//forward the request
	start := time.Now()
	mon.oxy.ServeHTTP(w, req)
	end := time.Now().Sub(start)

	//report all logging information
	meter := MeterMessage{
		OperationID:   operationID,
		Client:        req.RemoteAddr,
		Method:        method,
		Kind:          req.Method,
		RequestLenght: req.ContentLength,
		RequestTime:   end,
	}

	mon.push(requestID, meter)

	if mon.conf.ForwardTraffic {
		exchange.OperationID = operationID
		exchange.Client = req.RemoteAddr
		exchange.Method = method
		exchange.Kind = req.Method
		exchange.RequestLenght = req.ContentLength
		exchange.RequestTime = end
		exchange.RequestID = requestID

		mon.forward(requestID, exchange)
	}
}
func GetKey(token *jwt.Token) (interface{}, error) {

	set, err := jwk.FetchHTTP(jwksURL)
	if err != nil {
		return nil, err
	}

	keyID, ok := token.Header["kid"].(string)
	if !ok {
		return nil, errors.New("expecting JWT header to have string kid")
	}

	if key := set.LookupKeyID(keyID); len(key) == 1 {
		return key[0].Materialize()
	}

	return nil, errors.New("unable to find key")
}

func (mon *RequestMonitor) extractOperationId(path string, method string) string {

	optID, err := mon.cache.Match(path, method)

	if err != nil {
		log.Debugf("failed to match %s %s - %+v", path, method, err)
	}

	return optID
}

func (mon *RequestMonitor) responseInterceptor(resp *http.Response) error {

	if resp == nil {
		//in this case the request failed to produce a response
		log.Warn("Empty response.")
		return nil
	}

	//extract requestID
	var requestID string
	var operationID string

	if resp.Request != nil {
		requestID = resp.Request.Header.Get("X-DITAS-RequestID")
		operationID = resp.Request.Header.Get("X-DITAS-OperationID")
	}

	if resp.Request == nil {
		log.Warn("Could not close response, due to empty request")
		return nil
	}

	if requestID == "" {

		requestID = mon.generateRequestID(resp.Request.RemoteAddr)

	}

	meter := MeterMessage{
		OperationID:    operationID,
		RequestID:      requestID,
		ResponseCode:   resp.StatusCode,
		ResponseLength: resp.ContentLength,
	}
	mon.push(requestID, meter)

	if !mon.conf.ForwardTraffic {
		return nil
	}

	//read the body and reset the reader (otherwise it will not be availible to the client)
	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		log.Printf("Error reading body: %v", err)
		return err
	}

	log.Infof("%s", string(body))

	resp.ContentLength = int64(len(body))
	resp.Body = ioutil.NopCloser(bytes.NewReader(body))

	//report logging information
	exchange := exchangeMessage{
		ResponseBody:   string(body),
		ResponseHeader: resp.Header,
	}

	exchange.OperationID = operationID
	exchange.RequestID = requestID
	exchange.ResponseCode = resp.StatusCode
	exchange.ResponseLength = resp.ContentLength

	mon.forward(requestID, exchange)
	return nil
}
