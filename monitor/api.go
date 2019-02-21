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
	"net/http"
	"net/url"
	"path/filepath"
	"time"

	"github.com/spf13/viper"
)

type Configuration struct {
	configDir string //the directory where all config files are located

	Endpoint    string   // the endpoint that all requests are send to
	endpointURL *url.URL //internal URL represetantion

	ElasticSearchURL string //eleasticSerach endpoint

	VDCName string // VDCName (used for the index name in elastic serach)

	Opentracing    bool   //tells the proxy if a tracing header should be injected
	ZipkinEndpoint string //zipkin endpoint

	UseACME       bool //if true the proxy will aquire a LetsEncrypt certificate for the SSL connection
	UseSelfSigned bool //if UseACME is false, the proxy can use self signed certificates

	ForwardTraffic      bool //if true all traffic is forwareded to the exchangeReporter
	ExchangeReporterURL string
}

type MeterMessage struct {
	RequestID   string `json:"request.id"`
	OperationID string `json:"request.operationID"`

	Timestamp     time.Time     `json:"@timestamp"`
	RequestLenght int64         `json:"request.length"`
	Kind          string        `json:"request.method,omitempty"`
	Client        string        `json:"request.client,omitempty"`
	Method        string        `json:"request.path,omitempty"`
	RequestTime   time.Duration `json:"request.requestTime"`

	ResponseCode   int   `json:"response.code,omitempty"`
	ResponseLength int64 `json:"response.length,omitempty"`
}

type exchangeMessage struct {
	MeterMessage
	RequestID string `json:"id"`

	Timestamp time.Time `json:"@timestamp"`

	RequestBody   string      `json:"request.body,omitempty"`
	RequestHeader http.Header `json:"request.header,omitempty"`

	ResponseBody   string      `json:"response.body,omitempty"`
	ResponseHeader http.Header `json:"response.header,omitempty"`
}

func readConfig() (Configuration, error) {

	err := viper.ReadInConfig()
	configuration := Configuration{}
	if err != nil {
		log.Error("failed to load config", err)
		return configuration, err
	}

	if viper.GetBool("verbose") {
		viper.Debug()
	}

	viper.Unmarshal(&configuration)

	url, err := url.Parse(configuration.Endpoint)
	if err != nil {
		log.Error("target URL could not be parsed", err)
		return configuration, err
	}

	configuration.endpointURL = url
	configuration.configDir = filepath.Dir(viper.ConfigFileUsed())
	log.Infof("using this config %+v", configuration)
	return configuration, nil
}
