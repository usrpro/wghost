package main

import (
	"context"
	"crypto/ed25519"
	"reflect"
	"testing"
	"time"

	"github.com/moapis/authenticator"
	"github.com/pascaldekloe/jwt"
	"google.golang.org/grpc/metadata"
)

func Test_dialAuthenticator(t *testing.T) {
	ectx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	type args struct {
		ctx       context.Context
		target    string
		audiences []string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			"Timeout",
			args{
				ectx,
				"127.0.0.1:2222",
				[]string{"some", "aud"},
			},
			true,
		},
		{
			"Success",
			args{
				context.Background(),
				"127.0.0.1:8765",
				[]string{"some", "aud"},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := dialAuthenticator(tt.args.ctx, tt.args.target, tt.args.audiences...); (err != nil) != tt.wantErr {
				t.Errorf("dialAuthenticator() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_authInterceptor(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var err error
	if auth, err = dialAuthenticator(ctx, "127.0.0.1:8765"); err != nil {
		t.Fatal(err)
	}

	ar, err := auth.Client.AuthenticatePwUser(
		context.Background(),
		&authenticator.UserPassword{
			User:     &authenticator.UserPassword_Email{Email: "admin@localhost"},
			Password: "admin",
		},
	)

	c := jwt.Claims{
		KeyID: "-1",
	}

	ejwt, err := c.EdDSASign(ed25519.NewKeyFromSeed([]byte("12345678901234567890123456789012")))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		ctx      context.Context
		wantResp interface{}
		wantErr  bool
	}{
		{
			"Missing jwt",
			ctx,
			nil,
			true,
		},
		{
			"Success",
			metadata.NewIncomingContext(ctx,
				metadata.New(map[string]string{"jwt": ar.GetJwt()}),
			),
			"REQUEST",
			false,
		},
		{
			"Retrieval error",
			metadata.NewIncomingContext(ctx,
				metadata.New(map[string]string{"jwt": string(ejwt)}),
			),
			nil,
			true,
		},
		{
			"JSON error",
			metadata.NewIncomingContext(ctx,
				metadata.New(map[string]string{"jwt": "/"}),
			),
			nil,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotResp, err := authInterceptor(tt.ctx, "REQUEST", nil, testHandler)
			if (err != nil) != tt.wantErr {
				t.Errorf("authInterceptor() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotResp, tt.wantResp) {
				t.Errorf("authInterceptor() = %v, want %v", gotResp, tt.wantResp)
			}
		})
	}
}
