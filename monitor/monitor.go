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
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/gbrlsnchs/jwt/v3"
	"github.com/gorilla/mux"
	atomic2 "go.uber.org/atomic"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"time"

	"github.com/spf13/viper"

	"github.com/opentracing/opentracing-go"
	zipkin "github.com/openzipkin/zipkin-go-opentracing"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/acme/autocert"

	"github.com/kabukky/httpscerts"

	"github.com/vulcand/oxy/forward"
	"github.com/vulcand/oxy/utils"

	spec "github.com/DITAS-Project/blueprint-go"
	uuid "github.com/satori/go.uuid"
)

var logger = logrus.New()
var log = logrus.NewEntry(logger)

func SetLogger(nLogger *logrus.Logger) {
	logger = nLogger
}

func SetLog(entty *logrus.Entry) {
	log = entty
}

//RequestMonitor data struct
type RequestMonitor struct {
	conf      Configuration
	blueprint *spec.Blueprint
	oxy       *forward.Forwarder

	monitorQueue chan MeterMessage

	reporter    ElasticReporter
	exporter    ExchangeAgent
	benExporter ExchangeAgent

	exchangeSecret *jwt.HMACSHA

	cache ResouceCache

	tombstone         *atomic2.Bool
	forwardingAddress string
	tombstoneKey      *rsa.PublicKey

	iam *iam
}

//NewManger Creates a new logging, tracing RequestMonitor
func NewManger() (*RequestMonitor, error) {

	configuration, err := readConfig()
	if err != nil {
		log.Error("could not read config!")
		return nil, err
	}
	//TODO: XXX needs testing
	blueprint, err := spec.ReadBlueprint("/etc/ditas/blueprint.json")

	if err != nil {
		if !configuration.Strict {
			log.Warn("could not read blueprint (monitoring quality will be degraded)")
		} else {
			log.Fatal("can't run in strict mode without a blueprint")
		}
	}

	return initManager(configuration, blueprint)
}

func initManager(configuration Configuration, blueprint *spec.Blueprint) (*RequestMonitor, error) {
	mng := &RequestMonitor{
		conf:         configuration,
		blueprint:    blueprint,
		monitorQueue: make(chan MeterMessage, 10),
		cache:        NewResourceCache(blueprint),
		iam:          NewIAM(configuration),
	}
	mng.tombstone = atomic2.NewBool(false)
	readTombstoneKey(configuration.TombstonePublicKeyLocation, mng)

	err := mng.initTracing()
	if err != nil {
		log.Errorf("failed to init tracer %+v", err)
	}

	//initialize proxy
	fwd, err := forward.New(
		forward.Stream(true),                                                     //allow for streaming
		forward.PassHostHeader(true),                                             //allow for headers to pass
		forward.ErrorHandler(utils.ErrorHandlerFunc(handleError)),                //use a custom error function
		forward.StateListener(forward.UrlForwardingStateListener(stateListener)), //log state changes of the lib
		forward.ResponseModifier(mng.responseInterceptor),                        //we want to observe resposnes
	)

	if err != nil {
		log.Errorf("failed to init oxy %+v", err)
		return nil, err
	}

	mng.oxy = fwd

	if !viper.GetBool("testing") {
		reporter, err := NewElasticReporter(configuration, mng.monitorQueue)
		if err != nil {
			log.Errorf("Failed to init elastic reporter %+v", err)
			return nil, err
		}
		mng.reporter = reporter

		if configuration.ForwardTraffic {
			mng.exchangeSecret = jwt.NewHS256([]byte(configuration.ExchangeSecret))
			if configuration.ExchangeReporterURL == "" {
				log.Error("forward traffic is set but no url specified, skipping...")
				configuration.ForwardTraffic = false
			} else {

				exporter, err := NewBufferedExchangeReporter(configuration.ExchangeReporterURL)
				if err != nil {
					log.Errorf("Failed to init exchange reporter %+v", err)
					return nil, err
				}
				mng.exporter = exporter
			}
		}

		if configuration.BenchmarkForward {
			if configuration.BMSURL == "" {
				log.Error("forward traffic is set but no url specified, skipping...")
				configuration.BenchmarkForward = false
			} else {

				benExporter, err := NewExchangeReporter(configuration.BMSURL)
				if err != nil {
					log.Errorf("Failed to init benchmark reporter %+v", err)
					return nil, err
				}
				mng.benExporter = benExporter
			}
		}
	}

	log.Info("Request-Monitor created")

	if viper.GetBool("testing") {
		//publish all data that usually goes into a network worker
		go func(q chan MeterMessage) {
			for {
				msg := <-q
				log.Infof("meter:%+v", msg)
			}
		}(mng.monitorQueue)
	}

	return mng, nil
}

func readTombstoneKey(keyLocation string, mng *RequestMonitor) {
	tombstoneKey, err := ioutil.ReadFile(keyLocation)
	if err != nil {
		log.Error("failed to read tombstone signature key.")
	} else {
		block, _ := pem.Decode(tombstoneKey)
		if block == nil {
			log.Error("failed to read tombstone signature key, invalid PEM block")
		} else {
			key, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				log.Errorf("failed to read tombstone signature key %+v", err)
			} else {
				mng.tombstoneKey = key.(*rsa.PublicKey)
			}
		}
	}
}

func stateListener(url *url.URL, state int) {
	if url != nil {
		log.Printf("url:%s - state:%d", url.String(), state)
	}
}

//TODO: XXX needs testing
func handleError(w http.ResponseWriter, req *http.Request, err error) {
	statusCode := http.StatusInternalServerError
	if e, ok := err.(net.Error); ok {
		if e.Timeout() {
			statusCode = http.StatusGatewayTimeout
		} else {
			statusCode = http.StatusBadGateway
		}
	} else if err == io.EOF {
		statusCode = http.StatusBadGateway
	}

	log.Errorf("reqest:%s suffered internal error:%d - %v+", req.URL, statusCode, err)

	w.WriteHeader(statusCode)

	_, err = w.Write([]byte(http.StatusText(statusCode)))
	if err != nil {
		log.Errorf("error writing message! %+v", err)
	}
}

func (mon *RequestMonitor) isTombStoned() bool {
	return mon.tombstone.Load()
}

func (mon *RequestMonitor) setTombstone(url string) {
	mon.forwardingAddress = url
	mon.tombstone.Store(true)
}

func (mon *RequestMonitor) resetTombstone() {
	mon.forwardingAddress = ""
	mon.tombstone.Store(false)
}

func (mon *RequestMonitor) generateRequestID(remoteAddr string) string {
	now := time.Now()
	return uuid.NewV5(uuid.NamespaceX500, fmt.Sprintf("%s-%d-%d", remoteAddr, now.Day(), now.Minute())).String()
}

func (mon *RequestMonitor) initTracing() error {
	if viper.GetBool("testing") {
		return nil
	}

	//TODO: XXX needs testing
	if mon.conf.Opentracing {
		log.Info("opentracing active")
		// Create our HTTP collector.
		collector, err := zipkin.NewHTTPCollector(mon.conf.ZipkinEndpoint)
		if err != nil {
			log.Errorf("unable to create Zipkin HTTP collector: %+v\n", err)
			return err
		}

		// Create our recorder.
		recorder := zipkin.NewRecorder(collector, false, "0.0.0.0:0", "request-monitor")

		// Create our tracer.
		tracer, err := zipkin.NewTracer(
			recorder,
			zipkin.ClientServerSameSpan(true),
			zipkin.TraceID128Bit(true),
		)
		if err != nil {
			log.Errorf("unable to create Zipkin tracer: %+v\n", err)
			return err
		}

		// Explicitly set our tracer to be the default tracer.
		opentracing.InitGlobalTracer(tracer)
	}
	return nil
}

func (mon *RequestMonitor) push(requestID string, message MeterMessage) {
	message.RequestID = requestID
	message.Timestamp = time.Now()
	mon.monitorQueue <- message
}

//TODO: XXX needs testing
func (mon *RequestMonitor) forward(requestID string, message ExchangeMessage) {
	message.RequestID = requestID
	message.Timestamp = time.Now()
	message.VDCID = mon.conf.VDCID
	message.BlueprintID = mon.conf.BlueprintID

	if mon.conf.ForwardTraffic {
		mon.exporter.Add(message)
	}
	if mon.conf.BenchmarkForward {
		if message.sample {
			mon.benExporter.Add(message)
		}
	}
}

func (mon *RequestMonitor) initMonitorAPI() {
	var router = mux.NewRouter()

	mon.initTombstoneAPI(router)
	mon.initExchangeAPI(router)

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

//Listen will start all worker threads and wait for incoming requests
func (mon *RequestMonitor) Listen() {

	mon.initMonitorAPI()
	//start parallel reporter threads
	mon.reporter.Start()

	if mon.conf.ForwardTraffic {
		mon.exporter.Start()
		defer mon.exporter.Stop()
	}

	if mon.conf.BenchmarkForward {
		mon.benExporter.Start()
		defer mon.benExporter.Stop()
	}

	defer mon.reporter.Stop()

	var m *autocert.Manager
	if mon.conf.UseACME {

		m = &autocert.Manager{
			Email:  "werner@tu-berlin.de",
			Prompt: autocert.AcceptTOS,
			HostPolicy: func(ctx context.Context, host string) error {
				//TODO: add sensible host model
				return nil
			},
			Cache: autocert.DirCache(".certs"),
		}

		httpsServer := &http.Server{
			Addr:      fmt.Sprintf(":%d", viper.GetInt("SSLPort")),
			Handler:   http.HandlerFunc(mon.serve),
			TLSConfig: &tls.Config{GetCertificate: m.GetCertificate},
		}

		go func() {
			log.Infof("using %d", viper.GetInt("SSLPort"))
			err := httpsServer.ListenAndServeTLS("", "")
			if err != nil {
				log.Errorf("httpsSrv.ListendAndServeTLS() failed with %s", err)
			}
		}()
	} else if mon.conf.UseSelfSigned {
		certDir := mon.conf.configDir
		if mon.conf.CertificateLocation != "" {
			certDir = mon.conf.CertificateLocation
		}

		cert := filepath.Join(certDir, "cert.pem")
		key := filepath.Join(certDir, "key.pem")

		err := httpscerts.Check(cert, key)
		if err != nil {
			log.Info("could not load self signed keys - generationg some")
			err = httpscerts.Generate(cert, key, "127.0.0.1:443")
			if err != nil {
				log.Fatal("Error: Couldn't create https certs.")
			}
		}
		httpsServer := &http.Server{
			Addr:    fmt.Sprintf(":%d", viper.GetInt("SSLPort")),
			Handler: http.HandlerFunc(mon.serve),
		}
		go func() {
			log.Infof("using %d", viper.GetInt("SSLPort"))
			err := httpsServer.ListenAndServeTLS(cert, key)
			if err != nil {
				log.Errorf("httpsSrv.ListendAndServeTLS() failed with %s", err)
			}
		}()
	}

	httpServer := &http.Server{
		Addr: fmt.Sprintf(":%d", viper.GetInt("Port")),
	}

	if m != nil {
		httpServer.Handler = m.HTTPHandler(http.HandlerFunc(mon.serve))
	} else {
		httpServer.Handler = http.HandlerFunc(mon.serve)
	}
	log.Infof("using %d", viper.GetInt("Port"))
	log.Info("request-monitor ready")
	err := httpServer.ListenAndServe()
	if err != nil {
		log.Errorf("httpsSrv.ListendAndServeTLS() failed with %s", err)
	}
}
