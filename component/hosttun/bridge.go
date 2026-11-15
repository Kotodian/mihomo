// Package hosttun connects overlay IP packets to mihomo's existing default TUN.
package hosttun

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"

	"github.com/metacubex/mihomo/log"
)

const packetQueueSize = 256

// Binding owns one overlay instance's address and reply sender.
type Binding struct {
	name    string
	ctx     context.Context
	cancel  context.CancelFunc
	send    func(context.Context, []byte) error
	packets chan []byte
	done    chan struct{}

	// Protected by shared.Mutex.
	address netip.Addr
	closed  bool
}

type packetDevice interface {
	inject([]byte) error
	addAddress(netip.Addr) error
	removeAddress(netip.Addr) error
}

type route struct {
	address netip.Addr
	binding *Binding
}

type routeTable struct {
	device packetDevice
	routes []route
}

var shared = struct {
	// Interface configuration can block. Neither packet direction takes this
	// control-plane lock; both use an immutable, atomically published table.
	sync.Mutex
	bindings map[*Binding]struct{}
	device   packetDevice
	aliases  map[netip.Addr]struct{}
	table    atomic.Pointer[routeTable]
}{
	bindings: make(map[*Binding]struct{}),
	aliases:  make(map[netip.Addr]struct{}),
}

// New registers an instance without creating a TUN. A reload of the same
// outbound retires its old binding even if existing proxy connections keep
// the old adapter alive. The old adapter cannot remove the new one's alias.
func New(ctx context.Context, name string, send func(context.Context, []byte) error) *Binding {
	ctx, cancel := context.WithCancel(ctx)
	b := &Binding{
		name:    name,
		ctx:     ctx,
		cancel:  cancel,
		send:    send,
		packets: make(chan []byte, packetQueueSize),
		done:    make(chan struct{}),
	}
	shared.Lock()
	for old := range shared.bindings {
		if old.name == name {
			old.cancel()
			old.closed = true
			delete(shared.bindings, old)
		}
	}
	shared.bindings[b] = struct{}{}
	if err := reconcileAddresses(); err != nil {
		log.Warnln("[TUN](%s) retire overlay address: %v", name, err)
	}
	shared.Unlock()
	go b.run()
	return b
}

func (b *Binding) run() {
	defer close(b.done)
	for {
		select {
		case <-b.ctx.Done():
			return
		case packet := <-b.packets:
			if b.ctx.Err() != nil {
				return
			}
			if err := b.send(b.ctx, packet); err != nil && b.ctx.Err() == nil {
				log.Debugln("[TUN](%s) overlay packet send failed: %v", b.name, err)
			}
		}
	}
}

// SetAddress updates the /32 alias on the existing TUN. An invalid address
// withdraws it, for example while DHCP has no lease. Repeated calls retry
// configuration failures, including aliases pending when a TUN attaches.
func (b *Binding) SetAddress(address netip.Addr) error {
	address = address.Unmap()
	if address.IsValid() && (!address.Is4() || address.IsUnspecified() || address.IsLoopback() || address.IsMulticast()) {
		return fmt.Errorf("invalid host TUN IPv4 address: %s", address)
	}
	shared.Lock()
	defer shared.Unlock()
	if b.closed || b.ctx.Err() != nil {
		return os.ErrClosed
	}
	// Withdraw the previous DHCP lease even if the new address conflicts.
	b.address = netip.Addr{}
	for existing := range shared.bindings {
		if existing != b && existing.ctx.Err() == nil && address.IsValid() && existing.address == address {
			_ = reconcileAddresses()
			return fmt.Errorf("host TUN address %s is already used by %s", address, existing.name)
		}
	}
	b.address = address
	return reconcileAddresses()
}

// Caller holds shared.Mutex. Only aliases actually installed by this bridge
// are published. Failed removals stay owned and are retried on the next update.
func reconcileAddresses() error {
	publishRoutes()
	if shared.device == nil {
		return nil
	}
	desired := make(map[netip.Addr]struct{}, len(shared.bindings))
	for b := range shared.bindings {
		if b.address.IsValid() && b.ctx.Err() == nil {
			desired[b.address] = struct{}{}
		}
	}
	var errs []error
	for address := range shared.aliases {
		if _, ok := desired[address]; ok {
			continue
		}
		if err := shared.device.removeAddress(address); err != nil {
			errs = append(errs, err)
		} else {
			delete(shared.aliases, address)
		}
	}
	for address := range desired {
		if _, ok := shared.aliases[address]; ok {
			continue
		}
		if err := shared.device.addAddress(address); err != nil {
			errs = append(errs, err)
		} else {
			shared.aliases[address] = struct{}{}
		}
	}
	publishRoutes()
	return errors.Join(errs...)
}

func publishRoutes() {
	table := &routeTable{device: shared.device}
	if shared.device != nil {
		for b := range shared.bindings {
			if _, ok := shared.aliases[b.address]; ok && b.ctx.Err() == nil {
				table.routes = append(table.routes, route{address: b.address, binding: b})
			}
		}
	}
	shared.table.Store(table)
}

// Inject delivers an unmodified IPv4 packet addressed to this instance to
// the host kernel. Packets for other destinations are never host-forwarded.
func (b *Binding) Inject(packet []byte) error {
	_, destination, ok := packetAddresses(packet)
	if !ok {
		return nil
	}
	if err := b.ctx.Err(); err != nil {
		return err
	}
	table := shared.table.Load()
	if table == nil || table.device == nil {
		return nil
	}
	for _, route := range table.routes {
		if route.binding == b && route.address == destination {
			length := int(packet[2])<<8 | int(packet[3])
			return table.device.inject(packet[:length])
		}
	}
	return nil
}

// Close stops the instance's sender and removes only its own address.
func (b *Binding) Close() error {
	b.cancel()
	shared.Lock()
	var err error
	if !b.closed {
		b.closed = true
		delete(shared.bindings, b)
		err = reconcileAddresses()
	}
	shared.Unlock()
	<-b.done
	return err
}

func attach(device packetDevice) error {
	shared.Lock()
	defer shared.Unlock()
	if shared.device != nil {
		return errors.New("default host TUN is already attached")
	}
	shared.device = device
	// An overlay address conflict must not prevent ordinary proxying.
	if err := reconcileAddresses(); err != nil {
		log.Warnln("[TUN] configure overlay aliases: %v", err)
	}
	return nil
}

func detach(device packetDevice) {
	shared.Lock()
	defer shared.Unlock()
	if shared.device != device {
		return
	}
	shared.device = nil
	publishRoutes()
	for address := range shared.aliases {
		if err := device.removeAddress(address); err != nil {
			log.Warnln("[TUN] remove overlay alias %s: %v", address, err)
		}
		delete(shared.aliases, address)
	}
}

// dispatch consumes replies only on the device to which the alias belongs.
// Bounded, nonblocking queues keep a slow overlay off the proxy packet path.
func dispatch(device packetDevice, packet []byte) bool {
	table := shared.table.Load()
	if table == nil || table.device != device || len(table.routes) == 0 {
		return false
	}
	source, _, ok := packetAddresses(packet)
	if !ok {
		return false
	}
	for _, route := range table.routes {
		if source != route.address {
			continue
		}
		b := route.binding
		if b.ctx.Err() == nil {
			length := int(packet[2])<<8 | int(packet[3])
			// Read/BatchRead and gVisor all reuse their packet storage.
			packet = append([]byte(nil), packet[:length]...)
			select {
			case b.packets <- packet:
			case <-b.ctx.Done():
			default:
			}
		}
		return true
	}
	return false
}

func packetAddresses(packet []byte) (netip.Addr, netip.Addr, bool) {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return netip.Addr{}, netip.Addr{}, false
	}
	headerLength := int(packet[0]&15) * 4
	totalLength := int(packet[2])<<8 | int(packet[3])
	if headerLength < 20 || totalLength < headerLength || totalLength > len(packet) {
		return netip.Addr{}, netip.Addr{}, false
	}
	source := netip.AddrFrom4([4]byte{packet[12], packet[13], packet[14], packet[15]})
	destination := netip.AddrFrom4([4]byte{packet[16], packet[17], packet[18], packet[19]})
	return source, destination, true
}
