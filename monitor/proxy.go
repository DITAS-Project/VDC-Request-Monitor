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
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"

	opentracing "github.com/opentracing/opentracing-go"
)

func (mon *RequestMonitor) serve(w http.ResponseWriter, req *http.Request) {
	var requestID = mon.generateRequestID(req.RemoteAddr)

	//validate Token
	if mon.serveIAM(w, req) {
		return
	}

	var exchange = mon.prepareExchange(w, req)
	method := req.URL.Path
	req.URL = mon.conf.endpointURL

	operationID := mon.extractOperationId(req.URL.Path, req.Method)

	if mon.blockNonBlueprintRequests(w, operationID) {
		return
	}

	mon.setRequestHeader(req.Header, requestID, operationID)

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

	if nil != exchange {
		exchange.OperationID = operationID
		exchange.Client = req.RemoteAddr
		exchange.Method = method
		exchange.Kind = req.Method
		exchange.RequestLenght = req.ContentLength
		exchange.RequestTime = end
		exchange.RequestID = requestID

		mon.forward(requestID, *exchange)
	}
}

func (mon *RequestMonitor) setRequestHeader(header http.Header, requestID string, operationID string) {
	//inject tracing header
	if mon.conf.Opentracing {
		_ = opentracing.GlobalTracer().Inject(
			opentracing.StartSpan("VDC-Request").Context(),
			opentracing.HTTPHeaders,
			opentracing.HTTPHeadersCarrier(header),
		)
	}
	//inject looging header
	header.Set("X-DITAS-RequestID", requestID)
	header.Set("X-DITAS-OperationID", operationID)
}

// return true if this needs to block the flow, false oterhwise
func (mon *RequestMonitor) serveIAM(w http.ResponseWriter, req *http.Request) bool {
	if mon.conf.UseIAM {
		//TODO handle X-DITAS-Callback
		if req.Method == http.MethodOptions || req.Method == http.MethodHead {
			return false
		}
		token, err := mon.validateIAM(req)
		if err != nil {
			w.Header().Add("X-DEBUG", fmt.Sprintf("redirecting due to IAM %+v", err))
			http.Redirect(w, req, mon.conf.IAMURL, 403)
			log.Debugf("redirecting due to IAM %+v", err)
			return true
		}

		if err := mon.attachIAMToRequest(req, token); err != nil {
			//TODO: what do we do!!
			w.Header().Add("X-DEBUG", fmt.Sprintf("redirecting due to IAM %+v", err))
			http.Redirect(w, req, mon.conf.IAMURL, 403)

			return false
		}

	}

	return false
}

func (mon *RequestMonitor) blockNonBlueprintRequests(w http.ResponseWriter, operationId string) bool {
	if mon.conf.Strict && operationId == "" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return true
	}
	return false
}

func (mon *RequestMonitor) prepareExchange(w http.ResponseWriter, req *http.Request) *ExchangeMessage {
	if mon.conf.ForwardTraffic {
		body, err := ioutil.ReadAll(req.Body)

		if err != nil {
			log.Printf("Error reading body: %v", err)
			http.Error(w, "can't read body", http.StatusBadRequest)
		}

		//enact proxy request
		req.ContentLength = int64(len(body))
		req.Body = ioutil.NopCloser(bytes.NewReader(body))

		return &ExchangeMessage{
			RequestBody:   string(body),
			RequestHeader: req.Header,
		}

	}
	return nil
}

func (mon *RequestMonitor) OptainLatesIAMKey(token *jwt.Token) (interface{}, error) {

	keyID, ok := token.Header["kid"].(string)
	if !ok {
		return nil, errors.New("expecting JWT header to have string kid")
	}

	if key := mon.iam.LookupKeyID(keyID); len(key) == 1 {
		return key[0].Materialize()
	}

	return mon.iam.GetNewKey(keyID)

}

func (mon *RequestMonitor) validateIAM(req *http.Request) (*jwt.Token, error) {
	authHeader := req.Header.Get("Authorization")

	if authHeader == "" {
		return nil, fmt.Errorf("no Authorization Header")
	}

	authHeaderComponentes := strings.Split(authHeader, " ")

	if len(authHeaderComponentes) != 2 {
		return nil, fmt.Errorf("header in wrong format")
	}

	if strings.ToLower(authHeaderComponentes[0]) != "bearer" {
		return nil, fmt.Errorf("header in wrong format")
	}

	tokenString := authHeaderComponentes[1]
	token, err := jwt.ParseWithClaims(tokenString, &DITASClaims{}, mon.OptainLatesIAMKey)
	if err != nil {
		return nil, fmt.Errorf("could not parse token, %+v", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("token nolonger valid")
	}

	return token, nil
}

func (mon *RequestMonitor) attachIAMToRequest(req *http.Request, token *jwt.Token) error {

	session, err := mon.iam.mapToContext(token)

	if err != nil {
		return err
	}

	for _, role := range session.roles {
		req.Header.Add("X-DITAS-ROLES", role)
	}

	req.Header.Add("X-DITAS-USER", session.user)

	return nil
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
	exchange := ExchangeMessage{
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
