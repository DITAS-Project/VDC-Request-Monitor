package monitor

import (
	"fmt"
	"net/http"
	"reflect"
	"testing"
	"time"

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

	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *jwt.Token
		wantErr bool
	}{
		{
			name:    "Header in wrong format",
			wantErr: true,
			fields: fields{
				conf: Configuration{
					UseIAM: true,
				},
			},
			args: args{
				req: &http.Request{
					Header: map[string][]string{
						"Authorization": []string{
							"ONLY_ONE_VALUE_NO_SPACE",
						},
					},
				},
			},
			want: nil,
		},
	}
	tests := []iAMTestCase{}
	tests = append(tests, makeIAMTest("Empty Header", "", "", nil, true))
	tests = append(tests, makeIAMTest("Header in wrong format only one value", "", "ONLY_ONE_VALUE_NO_SPACE", nil, true))
	tests = append(tests, makeIAMTest("Header in wrong format first not bearer", "", "Not_Bearer token", nil, true))
	tests = append(tests, makeIAMTest("Could not Parse Token nonsenstoken", "", "Bearer nonsenstoken", nil, true))
	tests = append(tests, makeIAMTest("Could not Parse Token no kid in header", "", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", nil, true))
	tests = append(tests, makeIAMTest("Could not Parse Token key fetch error", "nourl", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Imdhc2dhc2cifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.UoYdfy0Sj5_4ujQVBVj1g0BGOIdXljCIckoQcuUiHyM", nil, true))
	tests = append(tests, makeIAMTest("Unable to find Key", "https://www.googleapis.com/oauth2/v3/certs", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Imdhc2dhc2cifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.UoYdfy0Sj5_4ujQVBVj1g0BGOIdXljCIckoQcuUiHyM", nil, true))
	tests = append(tests, makeIAMTest("Token no longer valid", "http://127.0.0.1:8080/auth/realms/vdc_dummy/protocol/openid-connect/certs", "Bearer eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ1Mm43MW1jQWRIaDBxMS12QzJYMHVYX1lmZzNjY0VtaDJxT2hObTgwSGdRIn0.eyJqdGkiOiIzYTI0MmMyMS1lMDliLTRlOTgtYWMwOC1lNjJlNjRkOGVkZDkiLCJleHAiOjE1NDc2NTU2MDcsIm5iZiI6MCwiaWF0IjoxNTQ3NjU1MzA3LCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvYXV0aC9yZWFsbXMvdmRjX2R1bW15IiwiYXVkIjoiYWNjb3VudCIsInN1YiI6IjI0OTY2NDI0LTEzMjQtNDdmMy1hNTNlLTM2ZmQzMmJiMjZlMCIsInR5cCI6IkJlYXJlciIsImF6cCI6InRlc3RfY2xpZW50IiwiYXV0aF90aW1lIjowLCJzZXNzaW9uX3N0YXRlIjoiMmFmNDVkY2MtNDU4Ny00MWQ4LWFjZGUtM2ZlMjg1MzNmZTJjIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJkb2N0b3IiXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6ImVtYWlsIHByb2ZpbGUiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsIm5hbWUiOiJKb2huIERvZSIsInByZWZlcnJlZF91c2VybmFtZSI6InRlc3RfZG9jdG9yIiwiZ2l2ZW5fbmFtZSI6IkpvaG4iLCJmYW1pbHlfbmFtZSI6IkRvZSJ9.jKEPmwvCK3E46w5hwBr8WEQDcM1oMlmSmjO4anpx5fdMwk2TS7YgDFfqzzmZqOSeKt8Lw5L5VFGXB83rTf1AOOYy4rfKeImgH_3k_uvh31_dUzpg-7H4Tnwi0eiZiVJGE2iK3QoYCZdN8XmQltO9bvAEucvizb9cG2UnBcK8pCzqLzEfIxeE9oZHwrTo20s6SRGzY1vo96DwSG4weur3iJMpv4aSHjlQNXRbH3yTepucK6PxCoFNO8R7gxg7Ak4DVpA5gOJa5MM3V7U_ereT5xTNcrhYRq_a1B4Ey9tJvcr5Ud2HM1Y6myRKKpOyXxM-OJLggzOuL2eDv5EkRgexBQ", nil, true))

	//TODO get fresh token before the testing starts

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mon := &RequestMonitor{
				conf: tt.fields.conf,
				iam:  tt.fields.iam,
			}
			got, err := mon.validateIAM(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("RequestMonitor.validateIAM() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("RequestMonitor.validateIAM() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIAMContextMap(t *testing.T) {
	iam := &iam{}

	token := createValidToken("foo")

	context, err := iam.mapToContext(token)

	fmt.Printf("context=%+v due to %+v", context, err)

	if len(context.roles) != 1 {
		t.Fail()
	}
}

func createValidToken(secretKey interface{}) *jwt.Token {
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
					"Authorizathion": []string{
						header,
					},
				},
			},
		},
		want: token,
	}
}
