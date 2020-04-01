/*
This file is part wghost.

Wghost is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with wghost.  If not, see <https://www.gnu.org/licenses/>.
*/

package main

import (
	"context"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/inconshreveable/log15"
	"github.com/usrpro/wghost"
	"github.com/usrpro/wghost/implement"
	"google.golang.org/grpc"
)

func testHandler(ctx context.Context, req interface{}) (interface{}, error) {
	return req, nil
}

func Test_logInterceptor(t *testing.T) {
	tests := []struct {
		name     string
		info     *grpc.UnaryServerInfo
		wantResp interface{}
		wantErr  bool
	}{
		{
			"Not WgDeviceServer",
			&grpc.UnaryServerInfo{
				Server:     &wghost.UnimplementedWgServer{},
				FullMethod: "spanac",
			},
			"REQUEST",
			false,
		},
		{
			"WgDeviceServer",
			&grpc.UnaryServerInfo{
				Server:     implement.New("wgtest", log15.Root()),
				FullMethod: "spanac",
			},
			"REQUEST",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotResp, err := logInterceptor(context.Background(), "REQUEST", tt.info, testHandler)
			if (err != nil) != tt.wantErr {
				t.Errorf("logInterceptor() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotResp, tt.wantResp) {
				t.Errorf("logInterceptor() = %v, want %v", gotResp, tt.wantResp)
			}
		})
	}
}

func Test_run(t *testing.T) {
	tests := []struct {
		name string
		want int
	}{
		{
			"Success",
			0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc := make(chan os.Signal, 1)
			go func() {
				time.Sleep(time.Millisecond)
				sc <- os.Interrupt
			}()

			if got := run(sc); got != tt.want {
				t.Errorf("run() = %v, want %v", got, tt.want)
			}
		})
	}
}
