package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/docker/go-connections/nat"
	"github.com/lestrrat/go-jwx/jwk"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"

	jwt "github.com/dgrijalva/jwt-go"
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

	tests = append(tests, makeIAMTest("Token no longer valid", "http://127.0.0.1:8080/auth/realms/vdc_access/protocol/openid-connect/certs", "Bearer eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ1Mm43MW1jQWRIaDBxMS12QzJYMHVYX1lmZzNjY0VtaDJxT2hObTgwSGdRIn0.eyJqdGkiOiIzYTI0MmMyMS1lMDliLTRlOTgtYWMwOC1lNjJlNjRkOGVkZDkiLCJleHAiOjE1NDc2NTU2MDcsIm5iZiI6MCwiaWF0IjoxNTQ3NjU1MzA3LCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvYXV0aC9yZWFsbXMvdmRjX2R1bW15IiwiYXVkIjoiYWNjb3VudCIsInN1YiI6IjI0OTY2NDI0LTEzMjQtNDdmMy1hNTNlLTM2ZmQzMmJiMjZlMCIsInR5cCI6IkJlYXJlciIsImF6cCI6InRlc3RfY2xpZW50IiwiYXV0aF90aW1lIjowLCJzZXNzaW9uX3N0YXRlIjoiMmFmNDVkY2MtNDU4Ny00MWQ4LWFjZGUtM2ZlMjg1MzNmZTJjIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJkb2N0b3IiXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6ImVtYWlsIHByb2ZpbGUiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsIm5hbWUiOiJKb2huIERvZSIsInByZWZlcnJlZF91c2VybmFtZSI6InRlc3RfZG9jdG9yIiwiZ2l2ZW5fbmFtZSI6IkpvaG4iLCJmYW1pbHlfbmFtZSI6IkRvZSJ9.jKEPmwvCK3E46w5hwBr8WEQDcM1oMlmSmjO4anpx5fdMwk2TS7YgDFfqzzmZqOSeKt8Lw5L5VFGXB83rTf1AOOYy4rfKeImgH_3k_uvh31_dUzpg-7H4Tnwi0eiZiVJGE2iK3QoYCZdN8XmQltO9bvAEucvizb9cG2UnBcK8pCzqLzEfIxeE9oZHwrTo20s6SRGzY1vo96DwSG4weur3iJMpv4aSHjlQNXRbH3yTepucK6PxCoFNO8R7gxg7Ak4DVpA5gOJa5MM3V7U_ereT5xTNcrhYRq_a1B4Ey9tJvcr5Ud2HM1Y6myRKKpOyXxM-OJLggzOuL2eDv5EkRgexBQ", nil, true))

	if !testing.Short() {
		tokenString, token := getValidToken(t)
		tests = append(tests, makeIAMTest("Valid token", "http://127.0.0.1:8080/auth/realms/vdc_access/protocol/openid-connect/certs", fmt.Sprintf("Bearer %s", tokenString), token, false))

		tests = append(tests, makeIAMTest("Valid token cacheHit", "http://127.0.0.1:8080/auth/realms/vdc_access/protocol/openid-connect/certs", fmt.Sprintf("Bearer %s", tokenString), token, false))
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
	mon.conf.IAMURL = "http://127.0.0.1:8080"
	mon.conf.JWKSURL = "http://127.0.0.1:8080/auth/realms/vdc_access/protocol/openid-connect/certs"

	mon.iam = NewIAM(mon.conf)

	//first test a redirect
	req := httptest.NewRequest("GET", "http://vdc/ask", nil)
	w := httptest.NewRecorder()
	mon.serveIAM(w, req)

	if w.Code != 403 {
		t.Fatalf("request should have used 403 as it did not contain a token!")
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
	time := time.Now().Second()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"foo": "bar",
		"nbf": time,
		"iss": "test_issuer",
		"typ": "Bearer",
		"realm_access": map[string][]string{
			"roles": []string{
				"doctor",
			},
		},
		"exp": time + 1000,
	})
	//
	token.Header["kid"] = "testKey"

	return token
}

func makeIAMTest(name string, jwkurl string, header string, token *jwt.Token, wantErr bool) iAMTestCase {
	conf := Configuration{
		UseIAM:  true,
		JWKSURL: jwkurl,
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

func startKeyCloak(t *testing.T) string {

	ctx := context.Background()
	cli, err := client.NewEnvClient()
	if err != nil {
		t.Error(err)
		t.SkipNow()
		return ""
	}

	t.Log("connected to docker")

	resp, err := cli.ContainerCreate(ctx, &container.Config{
		Image: "ditas/keycloak:latest",
		Cmd:   []string{""},
		ExposedPorts: nat.PortSet{
			"8080/tcp": struct{}{},
		},
	}, &container.HostConfig{
		AutoRemove: true,
		PortBindings: nat.PortMap{
			"8080/tcp": []nat.PortBinding{
				{
					HostIP:   "0.0.0.0",
					HostPort: "8080",
				},
			},
		},
	}, nil, "keycloak_testing")
	if err != nil {
		t.Error(err)
		return ""
	}
	t.Log("created container")

	if err := cli.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{}); err != nil {
		t.Error(err)
		return ""
	}
	t.Log("started keycloak")

	waitForConnection(t, nil)

	return resp.ID
}

func stopKeyCloak(t *testing.T, id string) {
	ctx := context.Background()
	cli, err := client.NewEnvClient()
	if err != nil {
		t.Error(err)
	}

	if err := cli.ContainerStop(ctx, id, nil); err != nil {
		t.Fatal(err)
	}
}

func waitForConnection(t *testing.T, timeout *time.Duration) error {

	signal := make(chan bool)

	go func() {
		backoff := 2 * time.Second
		for {
			resp, err := http.Head("http://localhost:8080/auth/realms/vdc_access")
			if err != nil {
				fmt.Printf("tried to connect to keycloak %+v waiting %d seconds\n", err, backoff)

			} else {
				if resp.StatusCode < 400 {
					fmt.Printf("got resp from keycloak %d\n", resp.StatusCode)
					signal <- true
				} else {
					fmt.Printf("tried to connect to keycloak %d waiting %d seconds\n", resp.StatusCode, backoff)
				}
			}
			time.Sleep(backoff)
			backoff = backoff * 2
		}
	}()

	if timeout != nil {
		select {
		case <-signal:
			return nil
		case <-time.After(*timeout):
			return fmt.Errorf("all timedout - keycloak could not be reached")
		}
	} else {
		<-signal
		return nil
	}

}

type keycloakTokenResponse struct {
	AccessToken string `json:"access_token"`
}

func getValidToken(t *testing.T) (string, *jwt.Token) {

	res, err := http.PostForm("http://localhost:8080/auth/realms/vdc_access/protocol/openid-connect/token", map[string][]string{
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
