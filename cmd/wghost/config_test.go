package main

import (
	"os"
	"reflect"
	"testing"
	"time"
)

func TestServerConfig_writeOut(t *testing.T) {
	if err := Default.writeOut("config/default.json"); err != nil {
		t.Fatal(err)
	}
}

func Test_configure(t *testing.T) {
	type args struct {
		c           ServerConfig
		configFiles string
	}
	tests := []struct {
		name    string
		args    args
		want    *ServerConfig
		wantErr bool
	}{
		{
			"Non existing file",
			args{
				configFiles: "Foo.json",
			},
			nil,
			true,
		},
		{
			"unmarshal error",
			args{
				configFiles: "tests/error.json",
			},
			nil,
			true,
		},
		{
			"Success",
			args{
				configFiles: "config/default.json",
			},
			&Default,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := configure(tt.args.c, tt.args.configFiles)
			if (err != nil) != tt.wantErr {
				t.Errorf("configure() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("configure() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestServerConfig_logger(t *testing.T) {
	tests := []struct {
		name     string
		LogLevel string
		wantErr  bool
	}{
		{
			"Level error",
			"foo",
			true,
		},
		{
			"Success",
			"error",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &ServerConfig{
				LogLevel: tt.LogLevel,
			}
			_, err := c.logger()
			if (err != nil) != tt.wantErr {
				t.Errorf("ServerConfig.logger() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestServerConfig_grpcOpts(t *testing.T) {
	tests := []struct {
		name    string
		TLS     *TLSConfig
		wantErr bool
	}{
		{
			"Nil TLS",
			nil,
			false,
		},
		{
			"TLS file errors",
			&TLSConfig{
				"Foo",
				"Bar",
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &ServerConfig{
				TLS: tt.TLS,
			}
			_, err := c.grpcOpts()
			if (err != nil) != tt.wantErr {
				t.Errorf("ServerConfig.grpcOpts() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestServerConfig_listenAndServe(t *testing.T) {
	type fields struct {
		Addres   string
		Port     uint16
		Device   string
		LogLevel string
		TLS      *TLSConfig
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			"Logger error",
			fields{
				Addres:   "127.0.0.1",
				Port:     9999,
				Device:   "wgtest",
				LogLevel: "foo",
			},
			true,
		},
		{
			"Opts error",
			fields{
				Addres:   "127.0.0.1",
				Port:     9999,
				Device:   "wgtest",
				LogLevel: "debug",
				TLS: &TLSConfig{
					"Foo",
					"Bar",
				},
			},
			true,
		},
		{
			"Listen error",
			fields{
				Addres:   "127.0.0.1",
				Port:     9,
				Device:   "wgtest",
				LogLevel: "debug",
			},
			true,
		},
		{
			"Success",
			fields{
				Addres:   "127.0.0.1",
				Port:     9999,
				Device:   "wgtest",
				LogLevel: "debug",
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &ServerConfig{
				Addres:   tt.fields.Addres,
				Port:     tt.fields.Port,
				Device:   tt.fields.Device,
				LogLevel: tt.fields.LogLevel,
				TLS:      tt.fields.TLS,
			}

			sc := make(chan os.Signal, 1)
			go func() {
				time.Sleep(time.Millisecond)
				sc <- os.Interrupt
			}()

			if err := c.listenAndServe(sc); (err != nil) != tt.wantErr {
				t.Errorf("ServerConfig.listenAndServe() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
