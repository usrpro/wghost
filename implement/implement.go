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

package implement

import (
	"context"
	"fmt"
	"sync"

	"github.com/inconshreveable/log15"
	log "github.com/usrpro/clog15"
	"github.com/usrpro/wghost"
	"github.com/usrpro/wghost/internal/adapt"
	"github.com/usrpro/wghost/internal/parse"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// WgDeviceServer is a WgServer with additional
// Device methods for direct access.
type WgDeviceServer interface {
	wghost.WgServer
	ConfigureDevice(cfg wgtypes.Config) error
	Device() (*wgtypes.Device, error)
	Logger() log15.Logger
}

type wgServer struct {
	wghost.UnimplementedWgServer
	device string
	client *wgctrl.Client
	mtx    sync.RWMutex // protects client

	log log15.Logger
}

// New returns a WgDeviceServer implementation,
// with an initialized wgctrl.Client.
// New panic if the wgctrl.Client cannot be opened.
func New(device string, logger log15.Logger) WgDeviceServer {
	client, err := wgctrl.New()
	if err != nil {
		panic(fmt.Errorf("NewWgServer: %w", err))
	}

	return &wgServer{
		device: device,
		client: client,
		log:    logger.New("dev", device),
	}
}

// DeviceError signals errors when accessing the WireGuard device
type DeviceError struct {
	dev string
	err error
}

func (e *DeviceError) Error() string {
	return fmt.Sprintf("Device %q: %s", e.dev, e.err)
}

func (e *DeviceError) Unwrap() error {
	return e.err
}

func (s *wgServer) Logger() log15.Logger {
	return s.log
}

func (s *wgServer) ConfigureDevice(cfg wgtypes.Config) error {
	s.mtx.Lock()
	err := s.client.ConfigureDevice(s.device, cfg)
	s.mtx.Unlock()

	if err != nil {
		return &DeviceError{s.device, err}
	}

	return nil
}

func (s *wgServer) Device() (*wgtypes.Device, error) {
	s.mtx.RLock()
	dev, err := s.client.Device(s.device)
	s.mtx.RUnlock()

	if err != nil {
		return nil, &DeviceError{s.device, err}
	}

	return dev, nil
}

func (s *wgServer) AddPeer(ctx context.Context, pc *wghost.PeerConfig) (*wghost.ConfigSuccess, error) {
	wpc, err := parse.PeerConfig(pc)
	if err != nil {
		return nil, err
	}
	log.Debug(ctx, "Parsed", "peerConfig", wpc)

	cfg := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{wpc},
	}
	if err = s.ConfigureDevice(cfg); err != nil {
		return nil, err
	}

	log.Info(ctx, "Peer added", "pubKey", wpc.PublicKey)
	return &wghost.ConfigSuccess{}, nil
}

func logPeerKeys(peers []wgtypes.PeerConfig) []string {
	entries := make([]string, len(peers)*2)
	for i := 0; i < len(peers); i++ {
		ei := i * 2
		entries[ei] = fmt.Sprintf("key%d", i)
		entries[ei+1] = peers[i].PublicKey.String()
	}
	return entries
}

func (s *wgServer) SetPeers(ctx context.Context, pcl *wghost.PeerConfigList) (*wghost.ConfigSuccess, error) {
	wpcl, err := parse.PeerConfigList(pcl)
	if err != nil {
		return nil, err
	}
	log.Debug(ctx, "Parsed", "peerConfigList", wpcl)

	cfg := wgtypes.Config{
		ReplacePeers: pcl.GetReplacePeers(),
		Peers:        wpcl,
	}
	if err = s.ConfigureDevice(cfg); err != nil {
		return nil, err
	}

	log.Info(ctx, "Peers set", log15.Lazy{Fn: func() { logPeerKeys(wpcl) }})

	return &wghost.ConfigSuccess{}, nil
}

func findPeer(peers []wgtypes.Peer, pub wgtypes.Key) (*wghost.Peer, error) {
	for i := 0; i < len(peers); i++ {
		if peers[i].PublicKey == pub {
			return adapt.PeerToMsg(&peers[i])
		}
	}
	return nil, status.Errorf(codes.NotFound, "Peer %s not found", pub)
}

func (s *wgServer) GetPeer(ctx context.Context, pq *wghost.PeerQuery) (*wghost.Peer, error) {
	pub, err := parse.PeerQuery(pq)
	if err != nil {
		return nil, err
	}

	dev, err := s.Device()
	if err != nil {
		return nil, err
	}

	return findPeer(dev.Peers, pub)
}

func (s *wgServer) ListPeers(ctx context.Context, plq *wghost.PeerListQuery) (*wghost.PeerList, error) {
	dev, err := s.Device()
	if err != nil {
		return nil, err
	}

	return adapt.PeerListToMsg(dev.Peers)
}
