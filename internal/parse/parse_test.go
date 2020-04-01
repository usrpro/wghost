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

package parse

import (
	"errors"
	"fmt"
	"net"
	"reflect"
	"testing"

	"github.com/usrpro/wghost"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestError_Error(t *testing.T) {
	type fields struct {
		msg string
		err error
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			"Error string",
			fields{
				msg: "spanac",
				err: errors.New("Test error"),
			},
			"Parse spanac: Test error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pe := &Error{
				msg: tt.fields.msg,
				err: tt.fields.err,
			}
			if got := pe.Error(); got != tt.want {
				t.Errorf("ParseError.Error() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestError_Unwrap(t *testing.T) {
	type fields struct {
		msg string
		err error
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr error
	}{
		{
			"Unwrap",
			fields{
				msg: "Wrapper",
				err: errors.New("Wrapped"),
			},
			errors.New("Wrapped"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pe := &Error{
				msg: tt.fields.msg,
				err: tt.fields.err,
			}
			if err := pe.Unwrap(); err.Error() != tt.wantErr.Error() {
				t.Errorf("ParseError.Unwrap() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_newErrorr(t *testing.T) {
	type args struct {
		msg string
		err error
	}
	tests := []struct {
		name string
		args args
		want *Error
	}{
		{
			"New error",
			args{
				msg: "spanac",
				err: errors.New("Test error"),
			},
			&Error{
				msg: "spanac",
				err: errors.New("Test error"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := newError(tt.args.msg, tt.args.err); got == nil || got.Error() != tt.want.Error() {
				t.Errorf("parseErr() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPeerConfig(t *testing.T) {
	tests := []struct {
		name    string
		args    *wghost.PeerConfig
		wantW   wgtypes.PeerConfig
		wantErr bool
	}{
		{
			"PublicKey empty error",
			&wghost.PeerConfig{
				PublicKey:    "",
				PresharedKey: "",
				AllowedIPs:   []string{"0.0.0.0/0", "10.10.10.22/32", "192.168.1.0/24"},
			},
			wgtypes.PeerConfig{},
			true,
		},
		{
			"PublicKey invalid error",
			&wghost.PeerConfig{
				PublicKey:    "foobar",
				PresharedKey: "",
				AllowedIPs:   []string{"0.0.0.0/0", "10.10.10.22/32", "192.168.1.0/24"},
			},
			wgtypes.PeerConfig{},
			true,
		},
		{
			"PreSharedKey invalid error",
			&wghost.PeerConfig{
				PublicKey:    "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
				PresharedKey: "foobar",
				AllowedIPs:   []string{"0.0.0.0/0", "10.10.10.22/32", "192.168.1.0/24"},
			},
			wgtypes.PeerConfig{},
			true,
		},
		{
			"PreSharedKey empty succes",
			&wghost.PeerConfig{
				PublicKey:    "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
				PresharedKey: "",
				AllowedIPs:   []string{"0.0.0.0/0", "10.10.10.22/32", "192.168.1.0/24"},
			},
			wgtypes.PeerConfig{
				PublicKey:    wgtypes.Key{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
				PresharedKey: &wgtypes.Key{},
				AllowedIPs: []net.IPNet{
					{
						IP:   net.ParseIP("0.0.0.0"),
						Mask: net.CIDRMask(0, 32),
					},
					{
						IP:   net.ParseIP("10.10.10.22"),
						Mask: net.CIDRMask(32, 32),
					},
					{
						IP:   net.ParseIP("192.168.1.0"),
						Mask: net.CIDRMask(24, 32),
					},
				},
			},
			false,
		},
		{
			"PreSharedKey succes",
			&wghost.PeerConfig{
				PublicKey:    "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
				PresharedKey: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
				AllowedIPs:   []string{"0.0.0.0/0", "10.10.10.22/32", "192.168.1.0/24"},
			},
			wgtypes.PeerConfig{
				PublicKey:    wgtypes.Key{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
				PresharedKey: &wgtypes.Key{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2},
				AllowedIPs: []net.IPNet{
					{
						IP:   net.ParseIP("0.0.0.0"),
						Mask: net.CIDRMask(0, 32),
					},
					{
						IP:   net.ParseIP("10.10.10.22"),
						Mask: net.CIDRMask(32, 32),
					},
					{
						IP:   net.ParseIP("192.168.1.0"),
						Mask: net.CIDRMask(24, 32),
					},
				},
			},
			false,
		},
		{
			"ParseCIDR error",
			&wghost.PeerConfig{
				PublicKey:    "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
				PresharedKey: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
				AllowedIPs:   []string{"0.0.0.0/0", "foo", "192.168.1.0/24"},
			},
			wgtypes.PeerConfig{},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotW, err := PeerConfig(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("PeerConfig.Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if fmt.Sprint(gotW) != fmt.Sprint(tt.wantW) {
				t.Errorf("PeerConfig.Parse() = \n%v\nwant\n%v", gotW, tt.wantW)
			}
		})
	}
}

func TestPeerConfigList(t *testing.T) {
	tests := []struct {
		name    string
		args    *wghost.PeerConfigList
		want    []wgtypes.PeerConfig
		wantErr bool
	}{
		{
			"Success",
			&wghost.PeerConfigList{
				Peers: []*wghost.PeerConfig{
					{
						PublicKey:    "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
						PresharedKey: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
						AllowedIPs:   []string{"0.0.0.0/0", "10.10.10.22/32", "192.168.1.0/24"},
					},
				},
			},
			[]wgtypes.PeerConfig{{
				PublicKey:    wgtypes.Key{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
				PresharedKey: &wgtypes.Key{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2},
				AllowedIPs: []net.IPNet{
					{
						IP:   net.ParseIP("0.0.0.0"),
						Mask: net.CIDRMask(0, 32),
					},
					{
						IP:   net.ParseIP("10.10.10.22"),
						Mask: net.CIDRMask(32, 32),
					},
					{
						IP:   net.ParseIP("192.168.1.0"),
						Mask: net.CIDRMask(24, 32),
					},
				},
			}},
			false,
		},
		{
			"Error",
			&wghost.PeerConfigList{
				Peers: []*wghost.PeerConfig{
					{
						PublicKey:  "",
						AllowedIPs: []string{"0.0.0.0/0", "10.10.10.22/32", "192.168.1.0/24"},
					},
				},
			},
			nil,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := PeerConfigList(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("PeerConfigList.Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if fmt.Sprint(got) != fmt.Sprint(tt.want) {
				t.Errorf("PeerConfigList.Parse() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPeerQuery(t *testing.T) {
	tests := []struct {
		name    string
		args    *wghost.PeerQuery
		want    wgtypes.Key
		wantErr bool
	}{
		{
			"ParseKey error",
			&wghost.PeerQuery{
				PublicKey: "",
			},
			wgtypes.Key{},
			true,
		},
		{
			"Success",
			&wghost.PeerQuery{
				PublicKey: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
			},
			wgtypes.Key{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := PeerQuery(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("PeerQuery.Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PeerQuery.Parse() = %v, want %v", got, tt.want)
			}
		})
	}
}
