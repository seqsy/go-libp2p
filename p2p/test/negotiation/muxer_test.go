package negotiation

import (
	"context"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/seqsy/go-libp2p"
	"github.com/seqsy/go-libp2p/core/crypto"
	"github.com/seqsy/go-libp2p/core/peer"
	"github.com/seqsy/go-libp2p/core/protocol"
	"github.com/seqsy/go-libp2p/core/sec/insecure"
	"github.com/seqsy/go-libp2p/p2p/muxer/mplex"
	"github.com/seqsy/go-libp2p/p2p/muxer/yamux"
	"github.com/seqsy/go-libp2p/p2p/security/noise"
	tls "github.com/seqsy/go-libp2p/p2p/security/tls"
	"github.com/seqsy/go-libp2p/p2p/transport/tcp"

	"github.com/stretchr/testify/require"
)

var (
	yamuxOpt = libp2p.Muxer("/yamux", yamux.DefaultTransport)
	mplexOpt = libp2p.Muxer("/mplex", mplex.DefaultTransport)
)

type testcase struct {
	Name             string
	ServerPreference []libp2p.Option
	ClientPreference []libp2p.Option

	Error    string
	Expected protocol.ID
}

type security struct {
	Name   string
	Option libp2p.Option
}

func TestMuxerNegotiation(t *testing.T) {
	testcases := []testcase{
		{
			Name:             "server and client have the same preference",
			ServerPreference: []libp2p.Option{yamuxOpt, mplexOpt},
			ClientPreference: []libp2p.Option{yamuxOpt, mplexOpt},
			Expected:         "/yamux",
		},
		{
			Name:             "client only supports one muxer",
			ServerPreference: []libp2p.Option{yamuxOpt, mplexOpt},
			ClientPreference: []libp2p.Option{yamuxOpt},
			Expected:         "/yamux",
		},
		{
			Name:             "server only supports one muxer",
			ServerPreference: []libp2p.Option{yamuxOpt},
			ClientPreference: []libp2p.Option{mplexOpt, yamuxOpt},
			Expected:         "/yamux",
		},
		{
			Name:             "client preference preferred",
			ServerPreference: []libp2p.Option{yamuxOpt, mplexOpt},
			ClientPreference: []libp2p.Option{mplexOpt, yamuxOpt},
			Expected:         "/mplex",
		},
		{
			Name:             "no preference overlap",
			ServerPreference: []libp2p.Option{yamuxOpt},
			ClientPreference: []libp2p.Option{mplexOpt},
			Error:            "failed to negotiate stream multiplexer: protocols not supported",
		},
	}

	clientID, _, err := crypto.GenerateEd25519Key(rand.Reader)
	require.NoError(t, err)
	serverID, _, err := crypto.GenerateEd25519Key(rand.Reader)
	require.NoError(t, err)

	securities := []security{
		{Name: "noise", Option: libp2p.Security("/noise", noise.New)},
		{Name: "tls", Option: libp2p.Security("/tls", tls.New)},
		{Name: "insecure", Option: libp2p.Security("/insecure", insecure.NewWithIdentity)},
	}

	for _, tc := range testcases {
		tc := tc

		for _, sec := range securities {
			sec := sec

			t.Run(fmt.Sprintf("%s: %s", sec.Name, tc.Name), func(t *testing.T) {
				server, err := libp2p.New(
					libp2p.Identity(serverID),
					sec.Option,
					libp2p.ChainOptions(tc.ServerPreference...),
					libp2p.Transport(tcp.NewTCPTransport),
					libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
				)
				require.NoError(t, err)

				client, err := libp2p.New(
					libp2p.Identity(clientID),
					sec.Option,
					libp2p.ChainOptions(tc.ClientPreference...),
					libp2p.Transport(tcp.NewTCPTransport),
					libp2p.NoListenAddrs,
				)
				require.NoError(t, err)

				err = client.Connect(context.Background(), peer.AddrInfo{ID: server.ID(), Addrs: server.Addrs()})
				if tc.Error != "" {
					require.Error(t, err)
					require.ErrorContains(t, err, tc.Error)
					return
				}

				require.NoError(t, err)
				conns := client.Network().ConnsToPeer(server.ID())
				require.Len(t, conns, 1, "expected exactly one connection")
				require.Equal(t, tc.Expected, conns[0].ConnState().StreamMultiplexer)
			})
		}
	}
}
