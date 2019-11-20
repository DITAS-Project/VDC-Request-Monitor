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
	"strings"
	"time"

	"github.com/spf13/viper"
)

type Configuration struct {
	configDir string //the directory where all config files are located

	Endpoint    string   // the endpoint that all requests are send to
	endpointURL *url.URL //internal URL represetantion

	ElasticSearchURL string //eleasticSerach endpoint

	ElasticBasicAuth bool //if active we use basic auth
	ElasticUser      string
	ElasticPassword  string

	CertificateLocation string //the location certificates are read/written

	TombstoneSecret        string // the preshared secret that is used to sign tombstone commands
	InjectTombstoneHeader  bool
	TombstoneHeader        map[string]string
	ViolentConnectionDeath bool

	VDCName string // VDCName (used for the index name in elastic serach)

	VDCID       string
	BlueprintID string

	Opentracing    bool   //tells the proxy if a tracing header should be injected
	ZipkinEndpoint string //zipkin endpoint

	UseACME       bool //if true the proxy will aquire a LetsEncrypt certificate for the SSL connection
	UseSelfSigned bool //if UseACME is false, the proxy can use self signed certificates

	ForwardTraffic      bool //if true all traffic is forwareded to the exchangeReporter
	ExchangeReporterURL string
	ExchangeSecret      string

	UseIAM      bool   //if true, authentication is required for all requests
	KeyCloakURL string // url for keycloak

	IAMURL  string //deprecated
	JWKSURL string //deprecated

	BenchmarkForward bool
	BMSURL           string //PayloadGenerator URL

	IgnoreElastic bool

	Strict bool //enforce routing in blueprint

	Port    int
	SSLPort int

	InfrastructureID string //Infrastructure ID

	DemoMode bool
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

type ExchangeMessage struct {
	MeterMessage
	RequestID   string    `json:"id"`
	VDCID       string    `json:"vdcid"`
	BlueprintID string    `json:"bpid"`
	Timestamp   time.Time `json:"@timestamp"`

	sample bool

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

	_ = viper.Unmarshal(&configuration)

	return initConfiguration(configuration)
}

func initConfiguration(configuration Configuration) (Configuration, error) {
	if viper.IsSet("VDCName") {
		ids := strings.Split(viper.GetString("VDCName"), "-")

		if !viper.IsSet("VDCID") {
			if len(ids) >= 1 {
				configuration.VDCID = ids[1]
			}
		}

		if !viper.IsSet("BlueprintID") {
			if len(ids) >= 2 {
				configuration.BlueprintID = ids[0]
			}
		}
	}

	endpoint, err := url.Parse(configuration.Endpoint)
	if err != nil {
		log.Errorf("target URL could not be parsed %+v", err)
		return configuration, err
	}

	configuration.endpointURL = endpoint
	configuration.configDir = filepath.Dir(viper.ConfigFileUsed())
	log.Infof("using this config %+v", configuration)

	if configuration.UseIAM {
		//enable compability to old config files
		if configuration.KeyCloakURL == "" && configuration.JWKSURL != "" {
			configuration.KeyCloakURL = configuration.JWKSURL[:len(configuration.JWKSURL)-31]

			log.Infof("migrated to new config %s", configuration.KeyCloakURL)
		}
	}

	if viper.GetBool("verbose") {
		log.Print(configuration)
	}

	return configuration, nil
}
