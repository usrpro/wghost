// Package adapt is used for morphing wgtypes into gRPC message types.
package adapt

import (
	"fmt"

	"github.com/golang/protobuf/ptypes"
	"github.com/usrpro/wghost"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// PeerToMsg adapts a wgtypes.Peer into a gRPC Peer message
func PeerToMsg(p *wgtypes.Peer) (*wghost.Peer, error) {
	ts, err := ptypes.TimestampProto(p.LastHandshakeTime)
	if err != nil {
		return nil, fmt.Errorf("PeerToMsg: %w", err)
	}

	aips := make([]string, len(p.AllowedIPs))
	for i, ip := range p.AllowedIPs {
		aips[i] = ip.String()
	}

	return &wghost.Peer{
		PublicKey:         p.PublicKey.String(),
		PresharedKey:      p.PresharedKey.String(),
		LastHandshakeTime: ts,
		ReceiveBytes:      p.ReceiveBytes,
		TransmitBytes:     p.TransmitBytes,
		AllowedIPs:        aips,
		ProtocolVersion:   int32(p.ProtocolVersion),
	}, nil
}

// PeerListToMsg adapts a slice of wgtypes.Peer into a gRPC PeerList message
func PeerListToMsg(ps []wgtypes.Peer) (*wghost.PeerList, error) {
	peers := make([]*wghost.Peer, len(ps))
	for i, p := range ps {
		var err error
		if peers[i], err = PeerToMsg(&p); err != nil {
			return nil, fmt.Errorf("PeerListToMsg: %w", err)
		}
	}

	return &wghost.PeerList{Peers: peers}, nil
}
