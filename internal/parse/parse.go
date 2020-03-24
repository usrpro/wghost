package parse

import (
	"fmt"
	"net"

	"github.com/usrpro/wghost"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Error wraps an underlying error.
type Error struct {
	msg string
	err error
}

const (
	parseErrString = "Parse %s: %v"
)

func (e *Error) Error() string {
	return fmt.Sprintf(parseErrString, e.msg, e.err)
}

func (e *Error) Unwrap() error {
	return e.err
}

func newError(msg string, err error) *Error {
	return &Error{msg, err}
}

// PeerConfig creates a wgtypes.PeerConfig from the incomming message type.
func PeerConfig(p *wghost.PeerConfig) (w wgtypes.PeerConfig, err error) {
	if w.PublicKey, err = wgtypes.ParseKey(p.GetPublicKey()); err != nil {
		return wgtypes.PeerConfig{}, newError("PeerConfig PublicKey", err)
	}

	if psk := p.GetPresharedKey(); psk != "" {
		k, err := wgtypes.ParseKey(psk)
		if err != nil {
			return wgtypes.PeerConfig{}, newError("PeerConfig PreSharedKey", err)
		}
		w.PresharedKey = &k
	} else {
		w.PresharedKey = &wgtypes.Key{}
	}

	ai := p.GetAllowedIPs()
	w.AllowedIPs = make([]net.IPNet, len(ai))
	for i, a := range ai {
		_, net, err := net.ParseCIDR(a)
		if err != nil {
			return wgtypes.PeerConfig{}, newError("PeerConfig ParseCIDR", err)
		}
		w.AllowedIPs[i] = *net
	}

	return w, nil
}

// PeerConfigList creates a slice of wgtypes.PeerConfig from the incomming message type.
func PeerConfigList(pl *wghost.PeerConfigList) ([]wgtypes.PeerConfig, error) {
	peers := pl.GetPeers()
	ws := make([]wgtypes.PeerConfig, len(peers))

	for i, p := range peers {
		var err error
		if ws[i], err = PeerConfig(p); err != nil {
			return nil, fmt.Errorf("PeerConfigList %d: %w", i, err)
		}
	}

	return ws, nil
}

// PeerQuery parses the public key from the message
func PeerQuery(pq *wghost.PeerQuery) (wgtypes.Key, error) {
	key, err := wgtypes.ParseKey(pq.GetPublicKey())
	if err != nil {
		return wgtypes.Key{}, newError("PeerQuery ParseKey", err)
	}
	return key, nil
}
