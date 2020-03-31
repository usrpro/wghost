package implement

import (
	"context"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/inconshreveable/log15"
	"github.com/usrpro/wghost"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		device  string
		wantErr bool
	}{
		{
			"Success",
			"wg-test",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.device)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewWgServer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got == nil || got.(*wgServer).device != tt.device {
				t.Errorf("NewWgServer() = %v, want %v", got, tt.device)
			}
		})
	}
}

func TestDeviceError_Error(t *testing.T) {
	smt := errors.New("something")
	e := DeviceError{
		dev: "wg-test",
		err: smt,
	}
	want := "Device \"wg-test\": something"

	if got := e.Error(); got != want {
		t.Errorf("DeviceError.Error() = %v, want %v", got, want)
	}

	if got := e.Unwrap(); got != smt {
		t.Errorf("DeviceError.Error() = %v, want %v", got, smt)
	}
}

var errorServer *wgServer

func init() {
	s, err := New("wg-not-exist")
	if err != nil {
		log15.Crit("Test init", "err", err)
		os.Exit(1)
	}
	errorServer = s.(*wgServer)

	log15.LvlFilterHandler(log15.LvlDebug, log15.StdoutHandler)
}

func Test_wgServer_ConfigureDevice(t *testing.T) {
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		cfg     wgtypes.Config
		wantErr bool
	}{
		{
			"Error",
			wgtypes.Config{
				PrivateKey: &priv,
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := errorServer.ConfigureDevice(tt.cfg); (err != nil) != tt.wantErr {
				t.Errorf("wgServer.configureDevice() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_wgServer_Device(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{
			"Error",
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := errorServer.Device(); (err != nil) != tt.wantErr {
				t.Errorf("wgServer.readDevice() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_wgServer_AddPeer(t *testing.T) {
	type args struct {
		ctx context.Context
		pc  *wghost.PeerConfig
	}
	tests := []struct {
		name    string
		args    args
		want    *wghost.ConfigSuccess
		wantErr bool
	}{
		{
			"Parse error",
			args{
				context.Background(),
				&wghost.PeerConfig{
					PublicKey: "foobar",
				},
			},
			nil,
			true,
		},
		{
			"Device error",
			args{
				context.Background(),
				&wghost.PeerConfig{
					PublicKey:    "CB/qGb52i1ws6ZGySEYv3ClY873O7utCtaE0EYHGXUc=",
					PresharedKey: "t0FfdPsgFuNe6zOPsnQ6KxY10TfsgJ1qP4Qh4KmK1D0=",
					AllowedIPs:   []string{"0.0.0.0/0", "::/0"},
				},
			},
			nil,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := errorServer.AddPeer(tt.args.ctx, tt.args.pc)
			if (err != nil) != tt.wantErr {
				t.Errorf("wgServer.AddPeer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("wgServer.AddPeer() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_logPeerKeys(t *testing.T) {
	peers := []wgtypes.PeerConfig{
		{PublicKey: wgtypes.Key{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}},
		{PublicKey: wgtypes.Key{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2}},
		{PublicKey: wgtypes.Key{3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3}},
	}

	want := []string{
		"key0", "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
		"key1", "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
		"key2", "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=",
	}
	if got := logPeerKeys(peers); !reflect.DeepEqual(got, want) {
		t.Errorf("logPeerKeys() = \n%v\nwant\n%v", got, want)
	}
}

func Test_wgServer_SetPeers(t *testing.T) {
	type args struct {
		ctx context.Context
		pcl *wghost.PeerConfigList
	}
	tests := []struct {
		name    string
		args    args
		want    *wghost.ConfigSuccess
		wantErr bool
	}{
		{
			"Parse error",
			args{
				context.Background(),
				&wghost.PeerConfigList{
					Peers: []*wghost.PeerConfig{{
						PublicKey: "foobar",
					}},
				},
			},
			nil,
			true,
		},
		{
			"Device error",
			args{
				context.Background(),
				&wghost.PeerConfigList{
					Peers: []*wghost.PeerConfig{{
						PublicKey:    "CB/qGb52i1ws6ZGySEYv3ClY873O7utCtaE0EYHGXUc=",
						PresharedKey: "t0FfdPsgFuNe6zOPsnQ6KxY10TfsgJ1qP4Qh4KmK1D0=",
						AllowedIPs:   []string{"0.0.0.0/0", "::/0"},
					}},
				},
			},
			nil,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := errorServer.SetPeers(tt.args.ctx, tt.args.pcl)
			if (err != nil) != tt.wantErr {
				t.Errorf("wgServer.SetPeers() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("wgServer.SetPeers() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_findPeer(t *testing.T) {
	type args struct {
		peers []wgtypes.Peer
		pub   wgtypes.Key
	}
	tests := []struct {
		name    string
		args    args
		want    *wghost.Peer
		wantErr bool
	}{
		{
			"Peer found",
			args{
				peers: []wgtypes.Peer{
					{PublicKey: wgtypes.Key{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}},
					{PublicKey: wgtypes.Key{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2}},
					{PublicKey: wgtypes.Key{3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3}},
				},
				pub: wgtypes.Key{3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3},
			},
			&wghost.Peer{
				PublicKey: "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=",
			},
			false,
		},
		{
			"Not found",
			args{
				peers: []wgtypes.Peer{
					{PublicKey: wgtypes.Key{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}},
					{PublicKey: wgtypes.Key{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2}},
					{PublicKey: wgtypes.Key{3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3}},
				},
				pub: wgtypes.Key{4},
			},
			nil,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := findPeer(tt.args.peers, tt.args.pub)
			if (err != nil) != tt.wantErr {
				t.Errorf("findPeer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("findPeer() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_wgServer_GetPeer(t *testing.T) {
	type args struct {
		ctx context.Context
		pq  *wghost.PeerQuery
	}
	tests := []struct {
		name    string
		args    args
		want    *wghost.Peer
		wantErr bool
	}{
		{
			"Parse error",
			args{
				context.Background(),
				&wghost.PeerQuery{
					PublicKey: "foo",
				},
			},
			nil,
			true,
		},
		{
			"Device error",
			args{
				context.Background(),
				&wghost.PeerQuery{
					PublicKey: "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=",
				},
			},
			nil,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := errorServer.GetPeer(tt.args.ctx, tt.args.pq)
			if (err != nil) != tt.wantErr {
				t.Errorf("wgServer.GetPeer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("wgServer.GetPeer() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_wgServer_ListPeers(t *testing.T) {
	_, err := errorServer.ListPeers(context.Background(), nil)
	if err == nil {
		t.Errorf("wgServer.ListPeers() error = %v, wantErr %v", err, true)
	}
}
