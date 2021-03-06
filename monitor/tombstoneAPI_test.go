package monitor

import (
	"fmt"
	"github.com/gbrlsnchs/jwt/v3"
	"github.com/spf13/viper"
	"gopkg.in/h2non/gock.v1"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequestMonitor_initTombstoneAPI(t *testing.T) {
	defer gock.Off()

	//setup testing enviroment
	viper.Set("verbose", true)
	viper.Set("testing", true)

	//defualt config for this test
	conf := Configuration{
		configDir:        ".",
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

	//build config
	conf, err := initConfiguration(conf)
	if err != nil {
		t.Errorf("failed to build config %+v", err)
		return
	}
	matcher := gock.NewBasicMatcher()

	// Add a custom match function
	matcher.Add(func(req *http.Request, ereq *gock.Request) (bool, error) {
		return true, nil
	})

	//mock endpoint for valid requests, e.g. the running vdc before it is moved
	gock.New(conf.Endpoint).
		SetMatcher(matcher).
		Reply(200).
		JSON(map[string]string{"foo": "bar"})

	gock.Observe(gock.DumpRequest)
	//setting up the manger and all its functionality
	mng, err := initManager(conf, nil)
	if err != nil || mng == nil {
		t.Error("failed to create request monitor")
		return
	}

	proxyMethod := http.HandlerFunc(mng.serve)

	t.Run("test-Normal", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/test", conf.Endpoint), nil)
		if err != nil {
			t.Fatal(err)
		}
		//mock vdc request
		rr := httptest.NewRecorder()

		//test a normal request, tombstone is false and everything is normal
		proxyMethod.ServeHTTP(rr, req)

		result := rr.Result()
		if result.StatusCode > 200 {
			t.Fatalf("request was normal should have worked %d", result.StatusCode)
		}
	})

	gock.New(conf.Endpoint).
		SetMatcher(matcher).
		Reply(200).
		JSON(map[string]string{"foo": "bar"})

	gock.Observe(gock.DumpRequest)

	t.Run("test-OPTIONS", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodOptions, fmt.Sprintf("%s/test", conf.Endpoint), nil)
		if err != nil {
			t.Fatal(err)
		}
		rr := httptest.NewRecorder()
		proxyMethod.ServeHTTP(rr, req)

		result := rr.Result()
		if result.StatusCode > 200 {
			b, _ := ioutil.ReadAll(result.Body)

			t.Fatalf("request was normal should have worked %d - %s", result.StatusCode, string(b))

		}
	})

	//simulate a vdc movement.
	tombstoneURL := "123.124.123.213:8081"
	gock.New(fmt.Sprintf("http://%s", tombstoneURL)).
		SetMatcher(matcher).
		Reply(200).
		JSON(map[string]string{"foo": "bar"})

	activateTombstoneMethod := http.HandlerFunc(mng.activateTombstone)
	deactivateTombstoneMethod := http.HandlerFunc(mng.deactivateTombstone)

	//generate the signature for this movement
	token, err := jwt.Sign(jwt.Payload{}, mng.tombstoneSecret)
	tokenString := fmt.Sprintf("Bearer %s", string(token))

	t.Run("test-tombstone-activation-fail", func(t *testing.T) {
		//create a tombstone request
		tombstoneRequest, err := http.NewRequest("POST", "http://localhost:3000/tombstone",
			strings.NewReader(tombstoneURL))
		if err != nil {
			t.Fatal(err)
		}

		//should fail
		rr := httptest.NewRecorder()
		tombstoneRequest.Body = ioutil.NopCloser(strings.NewReader(tombstoneURL)) //this is done as because we reuse this
		activateTombstoneMethod.ServeHTTP(rr, tombstoneRequest)
		if rr.Result().StatusCode != http.StatusUnauthorized {
			t.Fatal("security measure failed")
		}

		if mng.tombstone.Load() {
			t.Fatal("tombstone should not be set!")
		}

	})

	gock.New(conf.Endpoint).
		SetMatcher(matcher).
		Reply(200).
		JSON(map[string]string{"foo": "bar"})

	gock.Observe(gock.DumpRequest)
	t.Run("test-tombstone-activation-success", func(t *testing.T) {
		//should succeed
		tombstoneRequest, err := http.NewRequest("POST", "http://localhost:3000/tombstone",
			strings.NewReader(tombstoneURL))
		if err != nil {
			t.Fatal(err)
		}

		tombstoneRequest.Header.Set("Authorization", tokenString) //setting the actual signature, now the request should be valid
		rr := httptest.NewRecorder()
		activateTombstoneMethod.ServeHTTP(rr, tombstoneRequest)

		if rr.Result().StatusCode != http.StatusOK {
			t.Fatal("method should have succeeded")
		}

		if !mng.tombstone.Load() {
			t.Fatal("tombstone should be set!")
		}
		//should still work
		req, err := http.NewRequest("OPTIONS", fmt.Sprintf("%s/test", conf.Endpoint), nil)
		if err != nil {
			t.Fatal(err)
		}
		rr = httptest.NewRecorder()
		proxyMethod.ServeHTTP(rr, req)

		result := rr.Result()
		if result.StatusCode > 200 {
			t.Fatalf("request was normal should have worked %d", result.StatusCode)
		}

		//should be a redirect to tombstoneURL
		req, err = http.NewRequest("GET", fmt.Sprintf("%s/test", conf.Endpoint), nil)
		if err != nil {
			t.Fatal(err)
		}

		rr = httptest.NewRecorder()
		proxyMethod.ServeHTTP(rr, req)
		result = rr.Result()
		if result.StatusCode != http.StatusPermanentRedirect {
			t.Fatal("request was normal should have worked")
		}

		fmt.Println(result.Header.Get("Location"))
		if len(result.Header.Get("X-VDC-Location")) == 0 {
			t.Fatalf("X-VDC-Location should  be set to %s but was %s", tombstoneURL, result.Header.Get("X-VDC-Location"))
		}
		fmt.Println(result.Header.Get("X-VDC-Location"))
	})

	t.Run("test-tombstone-deactivation", func(t *testing.T) {
		tombstoneRequest, err := http.NewRequest("POST", "http://localhost:3000/tombstone",
			strings.NewReader(tombstoneURL))
		if err != nil {
			t.Fatal(err)
		}

		tombstoneRequest.Header.Set("Authorization", tokenString)
		//send revive request
		rr := httptest.NewRecorder()
		tombstoneRequest.Body = nil
		deactivateTombstoneMethod.ServeHTTP(rr, tombstoneRequest)
		if rr.Result().StatusCode != http.StatusOK {
			t.Fatal("method should have succeeded")
		}

		//should no longer be true
		if mng.tombstone.Load() {
			t.Fatal("tombstone should be unset set!")
		}
	})

}
