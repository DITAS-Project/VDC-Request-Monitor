package monitor

import (
	"github.com/spf13/viper"
	"testing"
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

	if conf.BlueprintID != "test" {
		t.Fatalf("expected BlueprintID to be test was %s", conf.BlueprintID)
	}

	if conf.KeyCloakURL != "http://127.0.0.1:8080/auth/realms/vdc_acces" {
		t.Fatalf("expected KeyCloakURL to be http://127.0.0.1:8080/auth/realms/vdc_acces was %s", conf.KeyCloakURL)
	}
}
