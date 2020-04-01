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

// Package adapt is used for morphing wgtypes into gRPC message types.
package adapt

import (
	"fmt"
	"net"

	"github.com/golang/protobuf/ptypes"
	"github.com/usrpro/wghost"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// EndPointToMsg adapts a net.UDPAddrs into a gRPC Endpoint message
func EndPointToMsg(ep *net.UDPAddr) *wghost.Endpoint {
	if ep == nil || ep.IP == nil {
		return nil
	}

	return &wghost.Endpoint{
		IP:   ep.IP.String(),
		Port: int32(ep.Port),
		Zone: ep.Zone,
	}
}

var emptyKey = wgtypes.Key{}

// PeerToMsg adapts a wgtypes.Peer into a gRPC Peer message
func PeerToMsg(p *wgtypes.Peer) (*wghost.Peer, error) {
	wp := &wghost.Peer{
		PublicKey:       p.PublicKey.String(),
		Endpoint:        EndPointToMsg(p.Endpoint),
		ReceiveBytes:    p.ReceiveBytes,
		TransmitBytes:   p.TransmitBytes,
		ProtocolVersion: int32(p.ProtocolVersion),
	}

	if !p.LastHandshakeTime.IsZero() {
		var err error
		wp.LastHandshakeTime, err = ptypes.TimestampProto(p.LastHandshakeTime)
		if err != nil {
			return nil, fmt.Errorf("PeerToMsg: %w", err)
		}
	}

	if len(p.AllowedIPs) > 0 {
		wp.AllowedIPs = make([]string, len(p.AllowedIPs))
		for i, ip := range p.AllowedIPs {
			wp.AllowedIPs[i] = ip.String()
		}
	}

	if p.PresharedKey != emptyKey {
		wp.PresharedKey = p.PresharedKey.String()
	}

	return wp, nil
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
