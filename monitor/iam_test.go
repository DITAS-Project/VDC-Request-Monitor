package monitor

import (
	"encoding/json"
	"fmt"
	"github.com/lestrrat/go-jwx/jwk"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"

	kkc "github.com/DITAS-Project/KeycloakConfigClient/kcc"
	"github.com/dgrijalva/jwt-go"
)

type iAMTestCaseFields struct {
	conf Configuration
	iam  *iam
}
type iAMTestCaseArgs struct {
	req *http.Request
}

type iAMTestCase struct {
	name    string
	fields  iAMTestCaseFields
	args    iAMTestCaseArgs
	want    *jwt.Token
	wantErr bool
}

func TestRequestMonitor_validateIAM(t *testing.T) {
	if !testing.Short() {
		id := startKeyCloak(t)
		defer stopKeyCloak(t, id)
	}

	tests := []iAMTestCase{}

	//XXX refactor this!
	tests = append(tests, makeIAMTest("Empty Header", "", "", nil, true))
	tests = append(tests, makeIAMTest("Header in wrong format only one value", "", "ONLY_ONE_VALUE_NO_SPACE", nil, true))
	tests = append(tests, makeIAMTest("Header in wrong format first not bearer", "", "Not_Bearer token", nil, true))
	tests = append(tests, makeIAMTest("Could not Parse Token nonsenstoken", "", "Bearer nonsenstoken", nil, true))
	tests = append(tests, makeIAMTest("Could not Parse Token no kid in header", "", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", nil, true))
	tests = append(tests, makeIAMTest("Could not Parse Token key fetch error", "nourl", "Bearer eyJhbGciOiJIU!zI1NiIsInR5cCI6IkpXVCIsImtpZCI6Imdhc2dhc2cifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.UoYdfy0Sj5_4ujQVBVj1g0BGOIdXljCIckoQcuUiHyM", nil, true))
	tests = append(tests, makeIAMTest("Unable to find Key", "https://www.googleapis.com/oauth2/v3/certs", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Imdhc2dhc2cifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.UoYdfy0Sj5_4ujQVBVj1g0BGOIdXljCIckoQcuUiHyM", nil, true))

	tests = append(tests, makeIAMTest("Token no longer valid", "http://127.0.0.1:8080/auth/realms/vdc_access", "Bearer eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ1Mm43MW1jQWRIaDBxMS12QzJYMHVYX1lmZzNjY0VtaDJxT2hObTgwSGdRIn0.eyJqdGkiOiIzYTI0MmMyMS1lMDliLTRlOTgtYWMwOC1lNjJlNjRkOGVkZDkiLCJleHAiOjE1NDc2NTU2MDcsIm5iZiI6MCwiaWF0IjoxNTQ3NjU1MzA3LCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvYXV0aC9yZWFsbXMvdmRjX2R1bW15IiwiYXVkIjoiYWNjb3VudCIsInN1YiI6IjI0OTY2NDI0LTEzMjQtNDdmMy1hNTNlLTM2ZmQzMmJiMjZlMCIsInR5cCI6IkJlYXJlciIsImF6cCI6InRlc3RfY2xpZW50IiwiYXV0aF90aW1lIjowLCJzZXNzaW9uX3N0YXRlIjoiMmFmNDVkY2MtNDU4Ny00MWQ4LWFjZGUtM2ZlMjg1MzNmZTJjIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJkb2N0b3IiXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6ImVtYWlsIHByb2ZpbGUiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsIm5hbWUiOiJKb2huIERvZSIsInByZWZlcnJlZF91c2VybmFtZSI6InRlc3RfZG9jdG9yIiwiZ2l2ZW5fbmFtZSI6IkpvaG4iLCJmYW1pbHlfbmFtZSI6IkRvZSJ9.jKEPmwvCK3E46w5hwBr8WEQDcM1oMlmSmjO4anpx5fdMwk2TS7YgDFfqzzmZqOSeKt8Lw5L5VFGXB83rTf1AOOYy4rfKeImgH_3k_uvh31_dUzpg-7H4Tnwi0eiZiVJGE2iK3QoYCZdN8XmQltO9bvAEucvizb9cG2UnBcK8pCzqLzEfIxeE9oZHwrTo20s6SRGzY1vo96DwSG4weur3iJMpv4aSHjlQNXRbH3yTepucK6PxCoFNO8R7gxg7Ak4DVpA5gOJa5MM3V7U_ereT5xTNcrhYRq_a1B4Ey9tJvcr5Ud2HM1Y6myRKKpOyXxM-OJLggzOuL2eDv5EkRgexBQ", nil, true))

	if !testing.Short() {
		tokenString, token := getValidToken(t)
		tests = append(tests, makeIAMTest("Valid token", "http://127.0.0.1:8080/auth/realms/vdc_access", fmt.Sprintf("Bearer %s", tokenString), token, false))

		tests = append(tests, makeIAMTest("Valid token cacheHit", "http://127.0.0.1:8080/auth/realms/vdc_access", fmt.Sprintf("Bearer %s", tokenString), token, false))
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mon := &RequestMonitor{
				conf: tt.fields.conf,
				iam:  tt.fields.iam,
			}
			got, err := mon.validateIAM(tt.args.req)
			if (err != nil) != tt.wantErr {
				fmt.Printf("RequestMonitor.validateIAM() error = %v, wantErr %v\n", err, tt.wantErr)
				return
			}

			if !reflect.DeepEqual(got, tt.want) {
				fmt.Printf("RequestMonitor.validateIAM() = %v, want %v\n", got, tt.want)
			}

		})
	}
}

func TestRequestMonitor_serveIAM(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	id := startKeyCloak(t)
	defer stopKeyCloak(t, id)

	mon := RequestMonitor{}

	mon.conf.UseIAM = true
	mon.conf.KeyCloakURL = "http://127.0.0.1:8080/auth/realms/vdc_access"

	mon.iam = NewIAM(mon.conf)

	//first test a redirect
	req := httptest.NewRequest("GET", "http://vdc/ask", nil)
	w := httptest.NewRecorder()
	mon.serveIAM(w, req)

	if w.Code != 403 {
		t.Fatalf("request should have used 403 as it did not contain a token!")
	}

	req = httptest.NewRequest("HEAD", "http://vdc/ask", nil)
	w = httptest.NewRecorder()

	result := mon.serveIAM(w, req)

	if result {
		t.Fatal("IAM should ignore management header")
	}


	accessToken, _ := getValidToken(t)

	req = httptest.NewRequest("GET", "http://vdc/ask", nil)

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	w = httptest.NewRecorder()

	mon.serveIAM(w, req)
	fmt.Printf("%+v\n %+v\n", w.Result(), req.Header)

	if roles := req.Header.Get("X-DITAS-ROLES"); roles == "" {
		t.Fatalf("roles not in request context!")
	} else {
		t.Logf("found roles:%s", roles)
	}

	if user := req.Header.Get("X-DITAS-USER"); user == "" {
		t.Fatalf("user not in request context!")
	} else {
		t.Logf("found user:%s", user)
	}
}

func TestIAMContextMap(t *testing.T) {
	iam := &iam{}

	token := createValidToken()

	context, err := iam.mapToContext(token)

	fmt.Printf("context=%+v due to %+v\n", context, err)

	if len(context.roles) != 1 {
		t.Fail()
	}
}

func createValidToken() *jwt.Token {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &DITASClaims{
		StandardClaims: &jwt.StandardClaims{
			ExpiresAt: 0,
			Id:        "1245y4",
			Issuer:    "golang-test",
			Subject:   "12345678",
		},
		Relams: map[string][]string{
			"roles": []string{
				"test",
			},
		},
		User: "tester",
	})
	//
	token.Header["kid"] = "testKey"

	return token
}

func makeIAMTest(name string, keycloakURL string, header string, token *jwt.Token, wantErr bool) iAMTestCase {
	conf := Configuration{
		UseIAM:      true,
		KeyCloakURL: keycloakURL,
	}
	return iAMTestCase{
		name:    name,
		wantErr: wantErr,
		fields: iAMTestCaseFields{
			conf: conf,
			iam:  NewIAM(conf),
		},
		args: iAMTestCaseArgs{
			req: &http.Request{
				Header: map[string][]string{
					"Authorization": []string{
						header,
					},
				},
			},
		},
		want: token,
	}
}

var imaMutex = &sync.Mutex{}

func startKeyCloak(t *testing.T) string {
	id := startContainer(t, imaMutex,"keycloak_testing","ditas/keycloak:latest",[]int{8080,8000},"http://localhost:8000/v1/keys")
	setupTestingRealm(t)
	_ = waitForConnection("http://localhost:8080/auth/realms/vdc_access", nil)
	return id
}

func setupTestingRealm(t *testing.T) {
	var client, err = kkc.NewKCC("http://localhost:8000")
	if err != nil {
		t.Fatalf("failed to connect to keycloak admin api. %+v", err)
	}

	err = client.SendBlueprint(kkc.BluePrint{
		BlueprintID: "vdc_access",
		ClientId:    "vdc_client",
	})
	if err != nil {
		t.Fatalf("failed to update blueprint realm %+v", err)
	}

	err = client.SendConfig(kkc.Config{
		BlueprintID: "vdc_access",
		Roles:       []string{"tester"},
		Users: []kkc.UserConfig{
			{Username: "test", Password: "test", Roles: []string{"tester"}},
		},
	})
	if err != nil {
		t.Fatalf("failed to update users in realm  %+v", err)
	}

}

func stopKeyCloak(t *testing.T, id string) {
	stopContainer(t,id)
}


type keycloakTokenResponse struct {
	AccessToken string `json:"access_token"`
}

func getValidToken(t *testing.T) (string, *jwt.Token) {

	res, err := http.PostForm("http://127.0.0.1:8080/auth/realms/vdc_access/protocol/openid-connect/token", map[string][]string{
		"client_id":  []string{"vdc_client"},
		"username":   []string{"test"},
		"password":   []string{"test"},
		"grant_type": []string{"password"},
	})

	if err != nil {
		t.Fatal(err)
		return "", nil
	}

	buf, _ := ioutil.ReadAll(res.Body)

	var keycloakResponse keycloakTokenResponse
	json.Unmarshal(buf, &keycloakResponse)

	token, err := jwt.Parse(keycloakResponse.AccessToken, func(token *jwt.Token) (interface{}, error) {

		set, err := jwk.FetchHTTP("http://127.0.0.1:8080/auth/realms/vdc_access/protocol/openid-connect/certs")
		if err != nil {
			return nil, err
		}

		keyID, _ := token.Header["kid"].(string)

		if key := set.LookupKeyID(keyID); len(key) == 1 {
			return key[0].Materialize()
		}

		return nil, fmt.Errorf("failed to get key for token")

	})

	if err != nil {
		t.Fatalf("failed to create valid test token %+v\n", err)
	}

	return keycloakResponse.AccessToken, token

}
