package easytier

import (
	"context"
	"net"
	"net/netip"

	"github.com/metacubex/mihomo/component/dialer"
	C "github.com/metacubex/mihomo/constant"
)

func listenUDP(ctx context.Context, d C.Dialer, network, address string) (net.PacketConn, error) {
	if direct, ok := d.(dialer.Dialer); ok {
		return direct.ListenPacketBound(ctx, network, address, netip.AddrPort{})
	}
	// Proxy and custom dialers retain ownership of their transport sockets.
	return d.ListenPacket(ctx, network, address, netip.AddrPort{})
}
