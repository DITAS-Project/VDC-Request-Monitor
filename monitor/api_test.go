package monitor

import (
	"testing"

	"github.com/spf13/viper"
)

func TestRequestMonitor_initConfiguration(t *testing.T) {
	//defualt config for this test
	conf := Configuration{
		configDir:        ".",
		Endpoint:         "http://foo.com",
		VDCName:          "test-1234", // VDCName (used for the index name in elastic serach)
		Opentracing:      false,       //tells the proxy if a tracing header should be injected
		UseACME:          false,       //if true the proxy will aquire a LetsEncrypt certificate for the SSL connection
		UseSelfSigned:    false,       //if UseACME is false, the proxy can use self signed certificates
		ForwardTraffic:   false,       //if true all traffic is forwareded to the exchangeReporter
		UseIAM:           true,        //if true, authentication is required for all requests
		BenchmarkForward: false,
		JWKSURL:          "http://127.0.0.1:8080/auth/realms/vdc_access/protocol/openid-connect/certs",
		IgnoreElastic:    true,
		Strict:           false,
		Port:             8888,
	}

	viper.Set("VDCName", conf.VDCName)

	conf, err := initConfiguration(conf)
	if err != nil {
		t.Fatalf("Failed to init config %+v", err)
	}

	if conf.VDCID != "1234" {
		t.Fatalf("expected VDCID to be 1234 was %s", conf.VDCID)
	}

	if conf.KeyCloakURL != "http://127.0.0.1:8080/auth/realms/vdc_acces" {
		t.Fatalf("expected KeyCloakURL to be http://127.0.0.1:8080/auth/realms/vdc_acces was %s", conf.KeyCloakURL)
	}
}

func TestBlueprintResolution(t *testing.T) {

	conf := Configuration{
		configDir:        "../resources",
		Endpoint:         "http://214.124.623.345:63340",
		TombstoneSecret:  "RealySecretMessage",
		VDCName:          t.Name(), // VDCName (used for the index name in elastic search)
		Opentracing:      false,    //tells the proxy if a tracing header should be injected
		UseACME:          false,    //if true the proxy will acquire a LetsEncrypt certificate for the SSL connection
		UseSelfSigned:    false,    //if UseACME is false, the proxy can use self signed certificates
		ForwardTraffic:   false,    //if true all traffic is forwarded to the exchangeReporter
		UseIAM:           false,    //if true, authentication is required for all requests
		BenchmarkForward: false,
		IgnoreElastic:    true,
		Strict:           false,
		Port:             8888,
	}

	blueprint, err := loadBlueprint(conf)
	if err != nil {
		t.Fatal("Need to be able to read the blueprint...", err)
	}

	mon, err := initManager(conf, blueprint)
	if err != nil {
		t.Fatal("Failed to init monitor", err)
	}

	if mon.conf.BlueprintID != blueprint.ID {
		t.FailNow()
	}

}
