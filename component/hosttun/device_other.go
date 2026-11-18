//go:build !darwin

package hosttun

import tun "github.com/metacubex/sing-tun"

const Supported = false

func Wrap(native tun.Tun, _ string, _ bool) (tun.Tun, error) {
	return native, nil
}
