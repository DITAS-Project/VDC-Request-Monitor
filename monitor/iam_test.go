package monitor

import (
	"net/http"
	"reflect"
	"testing"

	jwt "github.com/dgrijalva/jwt-go"
)

func TestRequestMonitor_validateIAM(t *testing.T) {
	type fields struct {
		conf Configuration
		iam  *iam
	}
	type args struct {
		req *http.Request
	}

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
						"Authorizathion": []string{
							"ONLY_ONE_VALUE_NO_SPACE",
						},
					},
				},
			},
			want: nil,
		},
	}

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
