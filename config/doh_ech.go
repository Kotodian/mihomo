package config

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"

	"github.com/metacubex/mihomo/component/ech/echparser"
	"github.com/metacubex/mihomo/component/trie"
	"github.com/metacubex/mihomo/dns"
)

type rawDoHECH struct {
	Config   string `yaml:"config" json:"config"`
	Fallback string `yaml:"fallback" json:"fallback"`
}

// configureDoHECH keeps the public ECH keys outside the server URL so applications
// with their own fragment parameter allowlist can manage the DNS server address.
func configureDoHECH(settings map[string]rawDoHECH, config *DNS) error {
	servers := [][]dns.NameServer{
		config.NameServer, config.Fallback, config.ProxyServerNameserver,
		config.DirectNameServer, config.DefaultNameserver,
	}
	for _, policy := range config.NameServerPolicy {
		servers = append(servers, policy.NameServers)
	}
	for _, policy := range config.ProxyServerPolicy {
		servers = append(servers, policy.NameServers)
	}
	for _, list := range servers {
		for i := range list {
			if err := configureDoHECHServer(settings, &list[i]); err != nil {
				return err
			}
		}
	}
	return nil
}

func configureDoHECHServer(settings map[string]rawDoHECH, server *dns.NameServer) error {
	pinned := server.Params["ech-config"]
	fallback := server.Params["ech-fallback"]
	if server.Net != "https" && pinned == "" && fallback == "" {
		return nil
	}

	u, err := url.Parse(server.Addr)
	if err != nil {
		return fmt.Errorf("invalid DoH upstream URL: %w", err)
	}
	setting, configured := settings[strings.ToLower(u.Hostname())]
	if configured {
		if pinned != "" || fallback != "" {
			return fmt.Errorf("DNS upstream %q: configure ECH once, either in dns.doh-ech or in the URL", server.Addr)
		}
		pinned, fallback = setting.Config, setting.Fallback
	} else if pinned == "" && fallback == "" {
		return nil
	}
	if u.Scheme != "https" || server.Net != "https" {
		return fmt.Errorf("DNS upstream %q: ECH requires HTTPS", server.Addr)
	}

	encoded, err := base64.StdEncoding.DecodeString(pinned)
	if err != nil || len(encoded) == 0 {
		return fmt.Errorf("DNS upstream %q: invalid ECHConfigList encoding", server.Addr)
	}
	configs, err := echparser.ParseECHConfigList(encoded)
	if err != nil || len(configs) == 0 {
		return fmt.Errorf("DNS upstream %q: invalid ECHConfigList", server.Addr)
	}
	if server.Params["skip-cert-verify"] == "true" || server.Params["name-cert-verify"] != "" {
		return fmt.Errorf("DNS upstream %q: ECH requires standard TLS verification", server.Addr)
	}
	if fallback != "" {
		if _, err := trie.ValidAndSplitDomain(fallback); err != nil ||
			strings.ContainsAny(fallback, "*+/:%?#") || strings.EqualFold(fallback, u.Hostname()) {
			return fmt.Errorf("DNS upstream %q: invalid ECH fallback hostname", server.Addr)
		}
	}
	if configured {
		server.Params["ech-config"] = pinned
		if fallback != "" {
			server.Params["ech-fallback"] = fallback
		}
	}
	return nil
}
