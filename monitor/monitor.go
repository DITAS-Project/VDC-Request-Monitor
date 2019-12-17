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
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/gbrlsnchs/jwt/v3"
	"github.com/gorilla/mux"
	atomic2 "go.uber.org/atomic"

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

const secretlength uint = 20

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

	exchangeSecret  *jwt.HMACSHA
	tombstoneSecret *jwt.HMACSHA
	demoSecret      *jwt.HMACSHA

	cache ResouceCache

	tombstone *atomic2.Bool
	death     *atomic2.Bool

	infrastructureType string

	forwardingAddress string
	tombstoneKey      *rsa.PublicKey
	circuits          []*circuitBreakingListener

	iam *iam

	demoSlow time.Duration
	demoFail bool
}

//NewManger Creates a new logging, tracing RequestMonitor
func NewManger() (*RequestMonitor, error) {

	configuration, err := readConfig()
	if err != nil {
		log.Error("could not read config!")
		return nil, err
	}
	blueprint, err := loadBlueprint(configuration)
	if err != nil {
		log.Errorf("Failed to load blueprint, degraded functionallity! %+v", err)
	}

	return initManager(configuration, blueprint)
}

func loadBlueprint(configuration Configuration) (*spec.Blueprint, error) {
	location, err := blueprintLocation(configuration)
	if err != nil {
		if !configuration.Strict {
			log.Warn(err.Error())
		} else {
			log.Fatal(err.Error())
		}
		return nil, err
	}

	blueprint, err := spec.ReadBlueprint(location)
	if err != nil {
		if !configuration.Strict {
			log.Warn("could not read blueprint (monitoring quality will be degraded)")
		} else {
			log.Fatal("can't run in strict mode without a blueprint")
		}
		return nil, err
	}
	return blueprint, nil
}

const ditasConfigDir = "/etc/ditas/"

func blueprintLocation(conf Configuration) (string, error) {

	p, _ := filepath.Abs(path.Join(ditasConfigDir, "blueprint.json"))
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		return p, nil
	} else {
		log.Infof("no blueprint @ %s", p)
	}

	p, _ = filepath.Abs(path.Join(conf.configDir, "blueprint.json"))
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		return p, nil
	} else {
		log.Infof("no blueprint @ %s", p)
	}

	return "", fmt.Errorf("could not locate a bluerint")

}

func generateSecretString() string {

	b := make([]byte, secretlength)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	s := fmt.Sprintf("%X", b)
	return s
}

func initManager(configuration Configuration, blueprint *spec.Blueprint) (*RequestMonitor, error) {

	if configuration.DANGERZONE {
		log.Warnln("YOU ARE RUNNING WITHOUT AUTHENTICATION! THIS IS DANGEROUS AND SHOULD ONLY BE DONE FOR TESTING!")
	}

	if blueprint != nil {
		configuration.BlueprintID = blueprint.ID
	} else {
		log.Warn("Did not find a blueprint, can't annotate data with blueprint and operation IDs.")
	}

	mng := &RequestMonitor{
		conf:         configuration,
		blueprint:    blueprint,
		monitorQueue: make(chan MeterMessage, 10),
		cache:        NewResourceCache(blueprint),
		iam:          NewIAM(configuration),
		circuits:     make([]*circuitBreakingListener, 0),
	}

	mng.tombstone = atomic2.NewBool(false)
	if configuration.TombstoneSecret == "" {
		log.Errorf("tomeston secret is not set")
		configuration.TombstoneSecret = generateSecretString()
		logger.Infof("using generated secret: %s", configuration.TombstoneSecret)
	}
	mng.tombstoneSecret = jwt.NewHS256([]byte(configuration.TombstoneSecret))

	if configuration.DemoSecret == "" {
		log.Errorf("demo secret is not set")
		configuration.DemoSecret = generateSecretString()
		logger.Infof("using generated secret: %s", configuration.DemoSecret)
	}
	mng.demoSecret = jwt.NewHS256([]byte(configuration.DemoSecret))

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
	} else {
		configuration.BenchmarkForward = false
		configuration.ForwardTraffic = false
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

	if mng.setupDemo() != nil {
		log.Fatalf("running in DEMO mode but could not Setup!")
	}

	return mng, nil
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

func (mon *RequestMonitor) AddCircuit(listener *circuitBreakingListener) {
	mon.circuits = append(mon.circuits, listener)
}

func (mon *RequestMonitor) tripCircuits() {
	if mon.conf.ViolentConnectionDeath {
		for _, c := range mon.circuits {
			err := c.FlushAllConnections()
			if err != nil {
				log.Error(err)
			}
		}
	}
}

func (mon *RequestMonitor) isTombStoned() bool {
	return mon.tombstone.Load()
}

func (mon *RequestMonitor) setTombstone(url string) {
	mon.forwardingAddress = url
	mon.tombstone.Store(true)

	mon.tripCircuits()
}

func (mon *RequestMonitor) resetTombstone() {
	mon.forwardingAddress = ""
	mon.tombstone.Store(false)

	mon.tripCircuits()
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
	if !viper.GetBool("testing") {
		if mon.conf.ForwardTraffic {
			mon.exporter.Add(message)
		}
		if mon.conf.BenchmarkForward {
			if message.sample {
				mon.benExporter.Add(message)
			}
		}
	}
}

func (mon *RequestMonitor) initMonitorAPI() {
	var router = mux.NewRouter()

	mon.initTombstoneAPI(router)
	mon.initExchangeAPI(router)
	mon.initDemoAPI(router)

	fmt.Println("Running server!")
	go func() {
		err := http.ListenAndServe(":3000", router)
		if err != nil {
			log.Errorf("encountered error in tombstone api %+v", err)
		}
	}()
}

func (mon *RequestMonitor) Authenticate(req *http.Request, secret *jwt.HMACSHA) error {
	if mon.conf.DANGERZONE {
		return nil
	}
	token := req.Header.Get("Authorization")
	if token != "" && len(token) > len("Bearer")+1 {
		token = token[len("Bearer")+1:]
		var payload jwt.Payload
		_, err := jwt.Verify([]byte(token), secret, &payload)
		if err != nil {
			return fmt.Errorf("could not validate token %+v", err)
		}
		return nil
	}
	return fmt.Errorf("no auth header set")
}

// circuitBreakingListener wraps a net.Listener
// allowing us to forceCose all open connections if the circuit is
// triggered.
type circuitBreakingListener struct {
	net.Listener

	activeConn map[net.Conn]struct{}
}

func (mon *RequestMonitor) newCircuit(list net.Listener) *circuitBreakingListener {
	circuit := &circuitBreakingListener{
		list,
		make(map[net.Conn]struct{}),
	}

	mon.AddCircuit(circuit)

	return circuit
}

type breakingConn struct {
	net.Conn
	circuit *circuitBreakingListener
}

func (conn *breakingConn) Close() error {
	//remove conn from poll
	log.Debugf("closed conn : %+v <-> %+v", conn.LocalAddr(), conn.RemoteAddr())
	delete(conn.circuit.activeConn, conn)
	return conn.Conn.Close()
}

func (l *circuitBreakingListener) FlushAllConnections() error {
	errors := make([]error, 0)
	for conn, _ := range l.activeConn {
		err := conn.Close()
		if err != nil {
			errors = append(errors, err)
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("encountered errors when flushing connections %+v", errors)
	} else {
		return nil
	}

}

func (l *circuitBreakingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()

	bacon := &breakingConn{conn, l}

	if conn != nil {
		log.Debugf("opened conn : %+v <-> %+v", conn.LocalAddr(), conn.RemoteAddr())
		l.activeConn[bacon] = struct{}{}
	}

	return bacon, err
}

//Listen will start all worker threads and wait for incoming requests
func (mon *RequestMonitor) Listen() {

	mon.initMonitorAPI()
	//start parallel reporter threads
	mon.reporter.Start()
	if !viper.GetBool("testing") {
		if mon.conf.ForwardTraffic {
			mon.exporter.Start()
			defer mon.exporter.Stop()
		}

		if mon.conf.BenchmarkForward {
			mon.benExporter.Start()
			defer mon.benExporter.Stop()
		}

		defer mon.reporter.Stop()
	}

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", viper.GetInt("Port")))
	if err != nil {
		log.Error("failed to listen ")
	}

	httpCircuit := mon.newCircuit(listener)

	httpServer := &http.Server{
		Addr: fmt.Sprintf(":%d", viper.GetInt("Port")),
	}

	httpServer.Handler = http.HandlerFunc(mon.serve)

	if mon.conf.UseACME || mon.conf.UseSelfSigned {
		sslListener, err := net.Listen("tcp", fmt.Sprintf(":%d", viper.GetInt("SLLPort")))
		if err != nil {
			log.Error("failed to listen ")
		}

		sslCircuit := mon.newCircuit(sslListener)

		if mon.conf.UseACME {
			httpsServer, cert, key, handler := createAutoCertServer(mon)

			//XXX: SET the ACME handler to accept HTTP challanges
			httpServer.Handler = handler

			go serveAndListenTLS(httpsServer, cert, key, sslCircuit)
		} else if mon.conf.UseSelfSigned {
			cert, key, httpsServer := createHTTPSServes(mon)

			go serveAndListenTLS(httpsServer, cert, key, sslCircuit)
		}
	}

	log.Info("request-monitor ready")

	serveAndListen(httpServer, httpCircuit)
}

func serveAndListen(httpServer *http.Server, httpCircuit *circuitBreakingListener) {
	log.Infof("using %d", viper.GetInt("Port"))

	err := httpServer.Serve(httpCircuit)
	if err != nil {
		log.Errorf("httpsSrv.ListendAndServeTLS() failed with %s", err)
	}
}

func createHTTPSServes(mon *RequestMonitor) (string, string, *http.Server) {
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
	return cert, key, httpsServer
}

func createAutoCertServer(mon *RequestMonitor) (*http.Server, string, string, http.Handler) {
	m := &autocert.Manager{
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
	cert := ""
	key := ""

	return httpsServer, cert, key, m.HTTPHandler(http.HandlerFunc(mon.serve))
}

func serveAndListenTLS(httpsServer *http.Server, cert string, key string, httpsCircuit *circuitBreakingListener) {
	log.Infof("using %d", viper.GetInt("SSLPort"))

	err := httpsServer.ServeTLS(httpsCircuit, cert, key)
	if err != nil {
		log.Errorf("httpsSrv.ListendAndServeTLS() failed with %s", err)
	}
}
