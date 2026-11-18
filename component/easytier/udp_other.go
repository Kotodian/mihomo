//go:build !darwin

package easytier

import (
	"context"
	"net"
	"net/netip"

	C "github.com/metacubex/mihomo/constant"
)

func listenUDP(ctx context.Context, d C.Dialer, network, address string) (net.PacketConn, error) {
	return d.ListenPacket(ctx, network, address, netip.AddrPort{})
}
