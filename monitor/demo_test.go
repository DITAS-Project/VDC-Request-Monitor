package monitor

import (
	"github.com/spf13/viper"
	"testing"
)

func TestRequestMonitor_demoMode(t *testing.T) {
	//defualt config for this test
	conf := Configuration{
		configDir:        "./.config/",
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
		DemoMode:         true,
		InfrastructureID: "2a9a0a15-a036-49ac-89ae-2fce9a0343ca",
	}

	viper.Set("VDCName", conf.VDCName)

	conf, err := initConfiguration(conf)
	if err != nil {
		t.Fatalf("Failed to init config %+v", err)
	}
	conf.configDir = "../.config/"
	blueprint, err := loadBlueprint(conf)
	if err != nil {
		t.Fatal(err.Error())
	}

	monitor, err := initManager(conf, blueprint)
	if err != nil {
		t.Fatal(err.Error())
	}

	err = monitor.setupDemo()
	if err != nil {
		t.Fatal(err.Error())
	}
	print("infrastructureType:", monitor.infrastructureType)

}
