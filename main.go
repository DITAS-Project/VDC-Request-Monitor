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

package main

import (
	"flag"

	"github.com/DITAS-Project/VDC-Request-Monitor/monitor"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
)

var (
	Build string
)

var logger = logrus.New()
var log *logrus.Entry

func init() {
	if Build == "" {
		Build = "Debug"
	}
	logger.Formatter = new(prefixed.TextFormatter)
	logger.SetLevel(logrus.DebugLevel)
	log = logger.WithFields(logrus.Fields{
		"prefix": "req-mon",
		"build":  Build,
	})
}

func setup() {
	viper.SetConfigName("monitor")
	viper.AddConfigPath("/etc/ditas/")
	viper.AddConfigPath("/.config/")
	viper.AddConfigPath(".config/")
	viper.AddConfigPath(".")

	//setup defaults
	viper.SetDefault("Port", 80)
	viper.SetDefault("SSLPort", 443)
	viper.SetDefault("Endpoint", "http://localhost:8080")
	viper.SetDefault("IgnoreElastic", false)
	viper.SetDefault("ElasticSearchURL", "http://localhost:9200")
	viper.SetDefault("ElasticUser", "")
	viper.SetDefault("ElasticPassword", "")
	viper.SetDefault("VDCName", "dummyVDC")
	viper.SetDefault("Opentracing", false)
	viper.SetDefault("CertificateLocation", "/tmp")
	viper.SetDefault("ZipkinEndpoint", "")
	viper.SetDefault("UseACME", false)
	viper.SetDefault("UseSelfSigned", true)
	viper.SetDefault("ForwardTraffic", false)
	viper.SetDefault("ExchangeReporterURL", "")
	viper.SetDefault("Strict", false)
	viper.SetDefault("UseIAM", false)
	viper.SetDefault("IAMURL", "")
	viper.SetDefault("JWKSURL", "")
	viper.SetDefault("KeyCloakURL", "")
	viper.SetDefault("testing", false)
	viper.SetDefault("InjectTombstoneHeader", true)

	//setup cmd interface
	flag.String("elastic", viper.GetString("ElasticSearchURL"), "used to define the elasticURL")
	flag.Bool("verbose", false, "for verbose logging")
	flag.Bool("testing", false, "starts agent in testing mode, no data will be persisted!")
	flag.Bool("Strict", false, "enforce strict routing, only allows routes present in the blueprint")
}

func main() {
	setup()

	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)
	pflag.Parse()

	err := viper.BindPFlags(pflag.CommandLine)
	if err != nil {
		log.Errorf("error parsing flags %+v", err)
	}

	if viper.GetBool("verbose") {
		logger.SetLevel(logrus.DebugLevel)
	}

	if viper.GetBool("testing") {
		logger.Warningln("Running in testing mode, do not use in production! No data logged or stored.")
	}

	monitor.SetLogger(logger)
	monitor.SetLog(log)

	mon, err := monitor.NewManger()

	if err != nil {
		log.Fatalf("could not start request monitor %+v", err)
	}

	mon.Listen()
}
