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
	"reflect"
	"testing"

	"github.com/inconshreveable/log15"
	"github.com/usrpro/wghost"
)

var testServer *wgServer

func init() {
	testServer = New("wgtest", log15.Root()).(*wgServer)
}

func TestPeer(t *testing.T) {
	pub := "CB/qGb52i1ws6ZGySEYv3ClY873O7utCtaE0EYHGXUc="
	psk := "t0FfdPsgFuNe6zOPsnQ6KxY10TfsgJ1qP4Qh4KmK1D0="
	aip := []string{"0.0.0.0/0", "::/0"}

	arg := &wghost.PeerConfig{
		PublicKey:    pub,
		PresharedKey: psk,
		AllowedIPs:   aip,
	}
	suc, err := testServer.AddPeer(context.Background(), arg)
	if err != nil {
		t.Fatal(err)
	}
	if suc == nil {
		t.Fatal("AddPeer success nil")
	}

	got, err := testServer.GetPeer(
		context.Background(),
		&wghost.PeerQuery{PublicKey: pub},
	)
	if err != nil {
		t.Fatal(err)
	}

	want := &wghost.Peer{
		PublicKey:       pub,
		PresharedKey:    psk,
		AllowedIPs:      aip,
		ProtocolVersion: 1,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("wgServer.GetPeer() = \n%v\nwant\n%v", got, want)
	}
}

func TestPeers(t *testing.T) {
	pub1 := "sKt9rkeKl/YIagiN3NHMTXuzrSrzK5UZcsJD0J2JXno="
	pub2 := "wBULkVL1vQ8/cnlNNiU2K7hXMfEAX0jhZvIpTtBzMGM="
	pub3 := "eJj2uagH+jcYjbNRfsb0bH2utaU5LXGGmIi5Mp7Wg34="

	psk1 := "vdTfeA52xTZGZS8v9NRS5QpqfGARTl/j1HMK5xxkS/Q="
	psk2 := "TRXFtF8qqBjIyE9x16EHtRvKuk5NIBz0IrV8WkRAHA8="
	psk3 := "2M8/clIlbIMlDL3fPvNOcCzmzmpBucsiVem/lfjUA8o="

	aip1 := []string{"192.168.0.22/32"}
	aip2 := []string{"192.168.1.22/32"}
	aip3 := []string{"192.168.2.22/32"}

	arg := &wghost.PeerConfigList{
		ReplacePeers: true,
		Peers: []*wghost.PeerConfig{
			{
				PublicKey:    pub1,
				PresharedKey: psk1,
				AllowedIPs:   aip1,
			},
			{
				PublicKey:    pub2,
				PresharedKey: psk2,
				AllowedIPs:   aip2,
			},
			{
				PublicKey:    pub3,
				PresharedKey: psk3,
				AllowedIPs:   aip3,
			},
		},
	}

	suc, err := testServer.SetPeers(context.Background(), arg)
	if err != nil {
		t.Fatal(err)
	}
	if suc == nil {
		t.Fatal("SetPeers success nil")
	}

	got, err := testServer.ListPeers(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}

	want := &wghost.PeerList{
		Peers: []*wghost.Peer{
			{
				PublicKey:       pub1,
				PresharedKey:    psk1,
				AllowedIPs:      aip1,
				ProtocolVersion: 1,
			},
			{
				PublicKey:       pub2,
				PresharedKey:    psk2,
				AllowedIPs:      aip2,
				ProtocolVersion: 1,
			},
			{
				PublicKey:       pub3,
				PresharedKey:    psk3,
				AllowedIPs:      aip3,
				ProtocolVersion: 1,
			},
		},
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("wgServer.ListPeers() = \n%v\nwant\n%v", got, want)
	}
}
