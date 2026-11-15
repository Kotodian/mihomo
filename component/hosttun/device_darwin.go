package hosttun

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"sync"
	"time"

	"github.com/metacubex/mihomo/log"

	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing/common/buf"
)

const Supported = true

type device struct {
	tun.DarwinTUN
	name      string
	index     int
	autoRoute bool
	closeOnce sync.Once
	closeErr  error
}

var _ tun.DarwinTUN = (*device)(nil)

// Wrap retains the native TUN's single reader, batch IO and optional gVisor
// endpoint. Only the default listener calls Wrap; additional TUNs are untouched.
func Wrap(native tun.Tun, name string, autoRoute bool) (tun.Tun, error) {
	batch, ok := native.(tun.DarwinTUN)
	if !ok {
		return native, nil
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	d := &device{DarwinTUN: batch, name: name, index: iface.Index, autoRoute: autoRoute}
	if err := attach(d); err != nil {
		return nil, err
	}
	return wrapGVisor(d), nil
}

func (d *device) Read(packet []byte) (int, error) {
	for {
		n, err := d.DarwinTUN.Read(packet)
		// Ordinary utun IO includes the four-byte address-family prefix.
		if n > tun.PacketOffset && dispatch(d, packet[tun.PacketOffset:n]) {
			if err != nil {
				return 0, err
			}
			continue
		}
		return n, err
	}
}

func (d *device) BatchRead() ([]*buf.Buffer, error) {
	for {
		packets, err := d.DarwinTUN.BatchRead()
		remaining := packets[:0]
		for _, packet := range packets {
			// Native batch buffers contain bare IP packets.
			if dispatch(d, packet.Bytes()) {
				packet.Release()
			} else {
				remaining = append(remaining, packet)
			}
		}
		for i := len(remaining); i < len(packets); i++ {
			packets[i] = nil
		}
		if len(remaining) != 0 || err != nil {
			return remaining, err
		}
	}
}

func (d *device) inject(packet []byte) error {
	// Native BatchWrite adds the AF prefix, uses nonblocking IO and shares
	// the native write lock with all the proxy stack's writers.
	return d.DarwinTUN.BatchWrite([]*buf.Buffer{buf.As(packet)})
}

func (d *device) addAddress(address netip.Addr) error {
	if !d.autoRoute {
		return fmt.Errorf("shared host stack requires tun.auto-route: true")
	}
	// Never adopt, move or later delete an address belonging to another owner,
	// including an existing alias on this same interface.
	interfaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	found := false
	for _, iface := range interfaces {
		if iface.Name == d.name && iface.Index == d.index {
			found = true
		}
		addresses, err := iface.Addrs()
		if err != nil {
			return err
		}
		for _, existing := range addresses {
			prefix, err := netip.ParsePrefix(existing.String())
			if err == nil && prefix.Addr().Unmap() == address {
				return fmt.Errorf("overlay address %s is already assigned to %s", address, iface.Name)
			}
		}
	}
	if !found {
		return fmt.Errorf("shared TUN %s has been replaced or closed", d.name)
	}
	if err := d.ifconfig("inet", address.String(), address.String(), "netmask", "255.255.255.255", "alias"); err != nil {
		return err
	}
	log.Infoln("[TUN] added overlay alias %s/32 to %s", address, d.name)
	return nil
}

func (d *device) removeAddress(address netip.Addr) error {
	interfaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	var iface *net.Interface
	for i := range interfaces {
		if interfaces[i].Name == d.name && interfaces[i].Index == d.index {
			iface = &interfaces[i]
			break
		}
	}
	if iface == nil {
		// Closing a TUN removes its addresses. Do not touch a replacement
		// interface which happens to reuse its name.
		return nil
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return err
	}
	for _, existing := range addresses {
		prefix, err := netip.ParsePrefix(existing.String())
		if err == nil && prefix.Addr().Unmap() == address {
			if err := d.ifconfig("inet", address.String(), "-alias"); err != nil {
				return err
			}
			log.Infoln("[TUN] removed overlay alias %s/32 from %s", address, d.name)
			return nil
		}
	}
	return nil
}

func (d *device) ifconfig(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	args = append([]string{d.name}, args...)
	output, err := exec.CommandContext(ctx, "/sbin/ifconfig", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("configure shared TUN %s: %w: %s", d.name, err, output)
	}
	return nil
}

func (d *device) Close() error {
	d.closeOnce.Do(func() {
		detach(d)
		d.closeErr = d.DarwinTUN.Close()
	})
	return d.closeErr
}
