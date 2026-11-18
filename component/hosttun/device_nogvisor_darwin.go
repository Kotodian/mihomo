//go:build !with_gvisor && darwin

package hosttun

import tun "github.com/metacubex/sing-tun"

func wrapGVisor(d *device) tun.Tun { return d }
