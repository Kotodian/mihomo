package dialer

import (
	"context"
	"net"
	"net/netip"
	"syscall"

	"github.com/metacubex/mihomo/component/iface"

	"golang.org/x/sys/unix"
)

func bindControl(ifaceIdx int) controlFn {
	return func(ctx context.Context, network, address string, c syscall.RawConn) (err error) {
		addrPort, err := netip.ParseAddrPort(address)
		if err == nil && !addrPort.Addr().IsGlobalUnicast() {
			return
		}
		return bindSocketToInterface(ifaceIdx)(ctx, network, address, c)
	}
}

func bindSocketToInterface(ifaceIdx int) controlFn {
	return func(_ context.Context, network, _ string, c syscall.RawConn) (err error) {
		var innerErr error
		err = c.Control(func(fd uintptr) {
			switch network {
			case "tcp6", "udp6", "ip6":
				innerErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, ifaceIdx)
			default:
				innerErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, ifaceIdx)
			}
		})

		if innerErr != nil {
			err = innerErr
		}

		return
	}
}

// ListenPacketBound keeps wildcard UDP listeners on the selected interface.
// Unlike a dial's remote address, a listener's local wildcard address must not
// suppress IP_BOUND_IF, or tunnel transport packets can re-enter the TUN.
func (d Dialer) ListenPacketBound(ctx context.Context, network, address string, remote netip.AddrPort) (net.PacketConn, error) {
	bindInterface := func(name string, lc *net.ListenConfig, _, address string, _ netip.AddrPort) (string, error) {
		ifaceObj, err := iface.ResolveInterface(name)
		if err != nil {
			return "", err
		}
		addControlToListenConfig(lc, bindSocketToInterface(ifaceObj.Index))
		return address, nil
	}
	lc, address, err := listenConfigWithInterfaceBinder(network, address, remote, d.Opt, bindInterface)
	if err != nil {
		return nil, err
	}
	return lc.ListenPacket(ctx, network, address)
}

func bindIfaceToDialer(ifaceName string, dialer *net.Dialer, _ string, _ netip.Addr) error {
	ifaceObj, err := iface.ResolveInterface(ifaceName)
	if err != nil {
		return err
	}

	addControlToDialer(dialer, bindControl(ifaceObj.Index))
	return nil
}

func bindIfaceToListenConfig(ifaceName string, lc *net.ListenConfig, _, address string, rAddrPort netip.AddrPort) (string, error) {
	ifaceObj, err := iface.ResolveInterface(ifaceName)
	if err != nil {
		return "", err
	}

	addControlToListenConfig(lc, bindControl(ifaceObj.Index))
	return address, nil
}

func ParseNetwork(network string, addr netip.Addr) string {
	return network
}
