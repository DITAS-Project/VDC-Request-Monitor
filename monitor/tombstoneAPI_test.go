package monitor

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/spf13/viper"
	"gopkg.in/h2non/gock.v1"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRequestMonitor_initTombstoneAPI(t *testing.T) {
	defer gock.Off()

	viper.Set("verbose", true)
	viper.Set("testing", true)

	f, err := ioutil.TempFile("", "public.pem")
	if err != nil {
		t.Fatalf("could not create key file %+v", err)
	}

	key, err := generateKeyPair(f)
	if err != nil {
		t.Fatalf("could not create key file %+v", err)
	}

	defer func() { _ = f.Close() }()
	tombstonePath, err := filepath.Abs(f.Name())
	if err != nil {
		t.Fatalf("could not create key file %+v", err)
	}

	conf := Configuration{
		configDir:                  ".",
		Endpoint:                   "http://foo.com",
		TombstonePublicKeyLocation: tombstonePath,
		VDCName:                    t.Name(), // VDCName (used for the index name in elastic serach)
		Opentracing:                false,    //tells the proxy if a tracing header should be injected
		UseACME:                    false,    //if true the proxy will aquire a LetsEncrypt certificate for the SSL connection
		UseSelfSigned:              false,    //if UseACME is false, the proxy can use self signed certificates
		ForwardTraffic:             false,    //if true all traffic is forwareded to the exchangeReporter
		UseIAM:                     false,    //if true, authentication is required for all requests
		BenchmarkForward:           false,
		IgnoreElastic:              true,
		Strict:                     false,
		Port:                       8888,
	}

	conf, err = initConfiguration(conf)
	if err != nil {
		t.Errorf("failed to build config %+v", err)
		return
	}

	gock.New(conf.Endpoint).
		Reply(200).
		JSON(map[string]string{"foo": "bar"})

	mng, err := initManager(conf, nil)
	if err != nil || mng == nil {
		t.Error("failed to create request monitor")
		return
	}

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/test", conf.Endpoint), nil)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	proxyMethod := http.HandlerFunc(mng.serve)

	//Mock HTTP request
	proxyMethod.ServeHTTP(rr, req)

	result := rr.Result()
	if result.StatusCode > 200 {
		t.Fatal("request was normal should have worked")
	}

	tombstoneURL := "http://bar.com"
	gock.New(tombstoneURL).
		Reply(200).
		JSON(map[string]string{"foo": "bar"})

	activateTombstoneMethod := http.HandlerFunc(mng.activateTombstone)
	deactivateTombstoneMethod := http.HandlerFunc(mng.deactivateTombstone)

	signature, err := generateSignature(key, tombstoneURL)
	if err != nil {
		t.Fatalf("could not generate signature %+v", err)
	}

	tombstoneRequest, err := http.NewRequest("POST", "http://localhost:3000/tombstone",
		strings.NewReader(tombstoneURL))
	if err != nil {
		t.Fatal(err)
	}

	//should fail
	rr = httptest.NewRecorder()
	tombstoneRequest.Body = ioutil.NopCloser(strings.NewReader(tombstoneURL))
	activateTombstoneMethod.ServeHTTP(rr, tombstoneRequest)
	if rr.Result().StatusCode != http.StatusUnauthorized {
		t.Fatal("security measure failed")
	}
	if mng.tombstone.Load() {
		t.Fatal("tombstone should not be set!")
	}

	//should succeed
	tombstoneRequest.Body = ioutil.NopCloser(strings.NewReader(tombstoneURL))
	tombstoneRequest.Header.Set("signature", signature)
	rr = httptest.NewRecorder()
	activateTombstoneMethod.ServeHTTP(rr, tombstoneRequest)
	if rr.Result().StatusCode != http.StatusOK {
		t.Fatal("method should have succeeded")
	}

	if !mng.tombstone.Load() {
		t.Fatal("tombstone should be set!")
	}

	//should be a redirect to tombstoneURL
	rr = httptest.NewRecorder()
	proxyMethod.ServeHTTP(rr, req)
	result = rr.Result()
	if result.StatusCode != http.StatusPermanentRedirect {
		t.Fatal("request was normal should have worked")
	}

	rr = httptest.NewRecorder()
	tombstoneRequest.Body = ioutil.NopCloser(strings.NewReader(tombstoneURL))
	deactivateTombstoneMethod.ServeHTTP(rr, tombstoneRequest)
	if rr.Result().StatusCode != http.StatusOK {
		t.Fatal("method should have succeeded")
	}

	if mng.tombstone.Load() {
		t.Fatal("tombstone should be unset set!")
	}
}

func generateSignature(key *rsa.PrivateKey, message string) (string, error) {
	hash := sha1.Sum([]byte(message))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, hash[:])

	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}

func generateKeyPair(pemfile *os.File) (*rsa.PrivateKey, error) {
	reader := rand.Reader
	bitSize := 2048
	key, err := rsa.GenerateKey(reader, bitSize)

	if err != nil {
		return nil, err
	}

	err = savePublicPEMKey(pemfile, &key.PublicKey)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func savePublicPEMKey(pemfile *os.File, pubkey *rsa.PublicKey) error {
	data, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return err
	}

	var pemkey = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: data,
	}

	err = pem.Encode(pemfile, pemkey)
	if err != nil {
		return err
	}
	return nil
}
