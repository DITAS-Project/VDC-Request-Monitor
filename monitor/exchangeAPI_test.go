package monitor

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"

	"github.com/gbrlsnchs/jwt/v3"
	"github.com/spf13/viper"
	"gopkg.in/h2non/gock.v1"

	"testing"
)

func TestRequestMonitor_exchangeAPI(t *testing.T) {
	defer gock.Off()

	//setup testing enviroment
	viper.Set("verbose", false)
	viper.Set("testing", false)

	//defualt config for this test
	conf := Configuration{
		configDir:           ".",
		Endpoint:            "http://foo.com",
		VDCName:             t.Name(), // VDCName (used for the index name in elastic serach)
		Opentracing:         false,    //tells the proxy if a tracing header should be injected
		UseACME:             false,    //if true the proxy will aquire a LetsEncrypt certificate for the SSL connection
		UseSelfSigned:       false,    //if UseACME is false, the proxy can use self signed certificates
		ForwardTraffic:      true,     //if true all traffic is forwareded to the exchangeReporter
		UseIAM:              false,    //if true, authentication is required for all requests
		BenchmarkForward:    false,
		IgnoreElastic:       true,
		Strict:              false,
		Port:                8888,
		ExchangeReporterURL: "localhost:9999",
		ExchangeSecret:      "notSoSecret",
	}

	//build config
	conf, err := initConfiguration(conf)
	if err != nil {
		t.Errorf("failed to build config %+v", err)
		return
	}

	//setting up the manger and all its functionality
	mng, err := initManager(conf, nil)
	if err != nil || mng == nil {
		t.Error("failed to create request monitor")
		return
	}
	const numMessages = 5
	//mock vdc request
	for i := 0; i < numMessages; i++ {
		url := fmt.Sprintf("%s/%d", conf.Endpoint, i)
		gock.New(url).
			Reply(200).
			JSON(map[string]string{"foo": "bar"})
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			t.Fatal(err)
		}

		rr := httptest.NewRecorder()
		proxyMethod := http.HandlerFunc(mng.serve)
		proxyMethod.ServeHTTP(rr, req)
		if rr.Code >= 400 {
			t.Fail()
		}

	}

	token, err := jwt.Sign(jwt.Payload{}, mng.exchangeSecret)
	//get collected messages
	collectMethod := http.HandlerFunc(mng.collectRawMessages)
	collectRequest, err := http.NewRequest("GET", "http://localhost:3000/messages", nil)

	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	collectMethod.ServeHTTP(rr, collectRequest)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("An Unauthroized request was allowed")
	}

	collectRequest.Header.Set("Authorization", fmt.Sprintf("Bearer %s", string(token)))
	fmt.Printf("Requuest:%+v\n", collectRequest)
	rr = httptest.NewRecorder()
	collectMethod.ServeHTTP(rr, collectRequest)
	if rr.Code != http.StatusOK {
		message, _ := ioutil.ReadAll(rr.Body)
		t.Fatalf("Status is wrong! %s", message)
	}

	var messages []ExchangeMessage
	bytes, err := ioutil.ReadAll(rr.Body)
	if err != nil {
		t.Fatalf("failed to read messages %+v", err)
	}
	fmt.Printf("Respnse:%s\n", string(bytes))
	err = json.Unmarshal(bytes, &messages)
	if err != nil {
		t.Fatalf("failed to parse messages %+v", err)
	}

	if len(messages) < numMessages {
		t.Errorf("some messages are missing!")

	}
	//t.Logf("got the following messages %+v", messages)
}
