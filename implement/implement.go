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

type wgServer struct {
	wghost.UnimplementedWgServer
	device string
	client *wgctrl.Client
	mtx    sync.RWMutex // protects client
}

// NewWgServer returns a WgServer implementation.
func NewWgServer(device string) (wghost.WgServer, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("NewWgServer: %w", err)
	}

	return &wgServer{
		device: device,
		client: client,
	}, nil
}

// DeviceError signals errors when accessing the WireGuard device
type DeviceError struct {
	dev string
	err error
}

func (e *DeviceError) Error() string {
	return fmt.Sprintf("Device %s config: %s", e.dev, e.err)
}

func (e *DeviceError) Unwrap() error {
	return e.err
}

func (s *wgServer) configureDevice(cfg wgtypes.Config) error {
	s.mtx.Lock()
	err := s.client.ConfigureDevice(s.device, cfg)
	s.mtx.Unlock()

	if err != nil {
		return &DeviceError{s.device, err}
	}

	return nil
}

func (s *wgServer) readDevice() (*wgtypes.Device, error) {
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
	if err = s.configureDevice(cfg); err != nil {
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
	if err = s.configureDevice(cfg); err != nil {
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

	dev, err := s.readDevice()
	if err != nil {
		return nil, err
	}

	return findPeer(dev.Peers, pub)
}

func (s *wgServer) ListPeers(ctx context.Context, plq *wghost.PeerListQuery) (*wghost.PeerList, error) {
	dev, err := s.readDevice()
	if err != nil {
		return nil, err
	}

	return adapt.PeerListToMsg(dev.Peers)
}
