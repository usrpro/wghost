package adapt

import (
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/usrpro/wghost"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestPeerToMsg(t *testing.T) {
	tests := []struct {
		name    string
		p       *wgtypes.Peer
		want    *wghost.Peer
		wantErr bool
	}{
		{
			"Success",
			&wgtypes.Peer{
				PublicKey:         wgtypes.Key{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
				PresharedKey:      wgtypes.Key{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2},
				LastHandshakeTime: time.Unix(333, 444),
				ReceiveBytes:      12000,
				TransmitBytes:     34000,
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
				ProtocolVersion: 88,
			},
			&wghost.Peer{
				PublicKey:    "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
				PresharedKey: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
				LastHandshakeTime: &timestamp.Timestamp{
					Seconds: 333,
					Nanos:   444,
				},
				ReceiveBytes:    12000,
				TransmitBytes:   34000,
				AllowedIPs:      []string{"0.0.0.0/0", "10.10.10.22/32", "192.168.1.0/24"},
				ProtocolVersion: 88,
			},
			false,
		},
		{
			"Time error",
			&wgtypes.Peer{
				PublicKey:         wgtypes.Key{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
				PresharedKey:      wgtypes.Key{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2},
				LastHandshakeTime: time.Unix(-62135596801, 0),
				ReceiveBytes:      12000,
				TransmitBytes:     34000,
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
				ProtocolVersion: 88,
			},
			nil,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := PeerToMsg(tt.p)
			if (err != nil) != tt.wantErr {
				t.Errorf("PeerToMsg() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PeerToMsg() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPeerListToMsg(t *testing.T) {
	tests := []struct {
		name    string
		ps      []wgtypes.Peer
		want    *wghost.PeerList
		wantErr bool
	}{
		{
			"Success",
			[]wgtypes.Peer{{
				PublicKey:         wgtypes.Key{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
				PresharedKey:      wgtypes.Key{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2},
				LastHandshakeTime: time.Unix(333, 444),
				ReceiveBytes:      12000,
				TransmitBytes:     34000,
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
				ProtocolVersion: 88,
			}},
			&wghost.PeerList{
				Peers: []*wghost.Peer{{
					PublicKey:    "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
					PresharedKey: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
					LastHandshakeTime: &timestamp.Timestamp{
						Seconds: 333,
						Nanos:   444,
					},
					ReceiveBytes:    12000,
					TransmitBytes:   34000,
					AllowedIPs:      []string{"0.0.0.0/0", "10.10.10.22/32", "192.168.1.0/24"},
					ProtocolVersion: 88,
				}},
			},
			false,
		},
		{
			"Time error",
			[]wgtypes.Peer{{
				PublicKey:         wgtypes.Key{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
				PresharedKey:      wgtypes.Key{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2},
				LastHandshakeTime: time.Unix(-62135596801, 0),
				ReceiveBytes:      12000,
				TransmitBytes:     34000,
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
				ProtocolVersion: 88,
			}},
			nil,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := PeerListToMsg(tt.ps)
			if (err != nil) != tt.wantErr {
				t.Errorf("PeerListToMsg() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PeerListToMsg() = %v, want %v", got, tt.want)
			}
		})
	}
}
