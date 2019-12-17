package monitor

import (
	"net/http"
	"testing"
)

type matchTest struct {
	sucess  bool
	method  string
	path    string
	opID    string
	request *http.Request
}

func TestRequestMatcher(t *testing.T) {

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
	mtc := NewResourceCache(blueprint)

	test := []matchTest{
		{sucess: true, method: "GET", path: "/GetSimplifiedDiagnostic", opID: "GetSimplifiedDiagnostic"},
		{sucess: true, method: "GET", path: "/GetSimplifiedDiagnostic?machine=CMS_LJ3Z4P", opID: "GetSimplifiedDiagnostic"},
		{sucess: true, method: "GET", path: "/caf/GetSimplifiedDiagnostic?machine=CMS_LJ3Z4P", opID: "GetSimplifiedDiagnostic"},
	}

	for _, tst := range test {

		opID, err := mtc.Match(tst.path, tst.method)

		if tst.sucess && err != nil {
			t.Fatalf("failed to match %s %s to %s cause %+v", tst.method, tst.path, tst.opID, err)
		}

		if opID != tst.opID {
			t.Fatalf("failed to match %s %s to %s matched to %s instead", tst.method, tst.path, tst.opID, opID)
		}

		t.Logf("matched %s %s to %s", tst.method, tst.path, opID)
	}

}

func TestRequestMatcherFromURL(t *testing.T) {

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

	monitor, err := initManager(conf, blueprint)
	if err != nil {
		t.Fatal(err.Error())
	}

	A, _ := http.NewRequest("GET", "http://localhost:3000/GetSimplifiedDiagnostic", nil)

	B, _ := http.NewRequest("GET", "http://localhost:3000/caf/GetSimplifiedDiagnostic?machine=CMS_LJ3Z4P", nil)

	C, _ := http.NewRequest("GET", "http://localhost:3000/favicon.ico", nil)

	test := []matchTest{
		{
			sucess:  true,
			method:  "GET",
			path:    "/GetSimplifiedDiagnostic",
			opID:    "GetSimplifiedDiagnostic",
			request: A,
		},
		{
			sucess:  true,
			method:  "GET",
			path:    "/caf/GetSimplifiedDiagnostic?machine=CMS_LJ3Z4P",
			opID:    "GetSimplifiedDiagnostic",
			request: B,
		},
		{
			sucess:  false,
			method:  "GET",
			path:    "",
			opID:    "",
			request: C,
		},
	}

	for _, tst := range test {
		opID := monitor.extractOperationIdFromRequest(tst.request)
		if opID != tst.opID {
			t.Fatalf("Expected %s for %+v but got %s", tst.opID, tst.request, opID)
		}

		t.Logf("Matched %s for %+v", opID, tst.request)
	}
}
