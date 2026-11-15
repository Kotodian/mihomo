//go:build with_gvisor && darwin

package hosttun

import (
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	tun "github.com/metacubex/sing-tun"
)

type gvisorDevice struct {
	*device
	native tun.GVisorTun
}

var _ tun.GVisorTun = (*gvisorDevice)(nil)
var _ tun.DarwinTUN = (*gvisorDevice)(nil)

func wrapGVisor(d *device) tun.Tun {
	if native, ok := d.DarwinTUN.(tun.GVisorTun); ok {
		return &gvisorDevice{device: d, native: native}
	}
	return d
}

func (d *gvisorDevice) WritePacket(packet *stack.PacketBuffer) (int, error) {
	return d.native.WritePacket(packet)
}

func (d *gvisorDevice) NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error) {
	endpoint, options, err := d.native.NewEndpoint()
	if err != nil {
		return nil, options, err
	}
	return &linkEndpoint{LinkEndpoint: endpoint, device: d.device}, options, nil
}

type linkEndpoint struct {
	stack.LinkEndpoint
	device *device
}

func (e *linkEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	if dispatcher == nil {
		e.LinkEndpoint.Attach(nil)
		return
	}
	e.LinkEndpoint.Attach(&networkDispatcher{NetworkDispatcher: dispatcher, device: e.device})
}

type networkDispatcher struct {
	stack.NetworkDispatcher
	device *device
}

func (d *networkDispatcher) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, packet *stack.PacketBuffer) {
	// Full gVisor reads the native fd directly, bypassing Read/BatchRead.
	// Intercept before its IP/TCP stack receives a host kernel reply.
	table := shared.table.Load()
	if protocol == header.IPv4ProtocolNumber && table != nil && table.device == d.device && len(table.routes) != 0 {
		view := packet.ToView()
		handled := dispatch(d.device, view.AsSlice())
		view.Release()
		if handled {
			return
		}
	}
	d.NetworkDispatcher.DeliverNetworkPacket(protocol, packet)
}
