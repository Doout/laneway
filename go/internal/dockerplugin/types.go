// Package dockerplugin implements Docker's libnetwork remote network-driver
// contract for policy-scoped Laneway networks.
package dockerplugin

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	OptionPolicy         = "laneway.policy"
	OptionEgressCIDRs    = "laneway.egress-cidrs"
	OptionIngress        = "laneway.ingress"
	OptionIngressSources = "laneway.ingress-sources"
	OptionExit           = "laneway.exit"
	OptionDNS            = "laneway.dns"
	OptionFailMode       = "laneway.fail-mode"
	OptionMTU            = "laneway.mtu"
	OptionNAT            = "laneway.nat"
)

var (
	ErrInvalid      = errors.New("dockerplugin: invalid configuration")
	ErrUnauthorized = errors.New("dockerplugin: policy is not controller-authorized")
	ErrConflict     = errors.New("dockerplugin: ownership conflict")
	ErrNotFound     = errors.New("dockerplugin: object not found")
)

type EgressPolicy string

const (
	EgressDirect     EgressPolicy = "direct"
	EgressSelective  EgressPolicy = "selective"
	EgressFullTunnel EgressPolicy = "full-tunnel"
	EgressIsolated   EgressPolicy = "isolated"
)

type IngressPolicy string

const (
	IngressDeny        IngressPolicy = "deny"
	IngressEstablished IngressPolicy = "established"
	IngressAllow       IngressPolicy = "allow"
)

// Policy is the normalized, immutable policy attached to a Docker network.
type Policy struct {
	Egress         EgressPolicy   `json:"egress"`
	EgressCIDRs    []netip.Prefix `json:"egress_cidrs,omitempty"`
	Ingress        IngressPolicy  `json:"ingress"`
	IngressSources []netip.Prefix `json:"ingress_sources,omitempty"`
	Exit           string         `json:"exit,omitempty"`
	DNS            []netip.Addr   `json:"dns,omitempty"`
	FailMode       string         `json:"fail_mode"`
	MTU            int            `json:"mtu"`
	NAT            bool           `json:"nat,omitempty"`
}

func ParsePolicy(options map[string]any) (Policy, error) {
	flat := flattenOptions(options)
	p := Policy{Egress: EgressDirect, Ingress: IngressDeny, FailMode: "closed", MTU: 1380}
	if value := flat[OptionPolicy]; value != "" {
		p.Egress = EgressPolicy(value)
	}
	if value := flat[OptionIngress]; value != "" {
		p.Ingress = IngressPolicy(value)
	}
	p.Exit = flat[OptionExit]
	if value := flat[OptionFailMode]; value != "" {
		p.FailMode = value
	}
	if value := flat[OptionMTU]; value != "" {
		mtu, err := strconv.Atoi(value)
		if err != nil || mtu < 576 || mtu > 9000 {
			return Policy{}, fmt.Errorf("%w: %s must be between 576 and 9000", ErrInvalid, OptionMTU)
		}
		p.MTU = mtu
	}
	if value := flat[OptionNAT]; value != "" {
		nat, err := strconv.ParseBool(value)
		if err != nil {
			return Policy{}, fmt.Errorf("%w: %s must be true or false", ErrInvalid, OptionNAT)
		}
		p.NAT = nat
	}
	var err error
	if p.EgressCIDRs, err = parsePrefixes(flat[OptionEgressCIDRs]); err != nil {
		return Policy{}, fmt.Errorf("%w: %s: %v", ErrInvalid, OptionEgressCIDRs, err)
	}
	if p.IngressSources, err = parsePrefixes(flat[OptionIngressSources]); err != nil {
		return Policy{}, fmt.Errorf("%w: %s: %v", ErrInvalid, OptionIngressSources, err)
	}
	if p.DNS, err = parseAddresses(flat[OptionDNS]); err != nil {
		return Policy{}, fmt.Errorf("%w: %s: %v", ErrInvalid, OptionDNS, err)
	}
	if err := p.Validate(); err != nil {
		return Policy{}, err
	}
	return p, nil
}

func (p Policy) Validate() error {
	switch p.Egress {
	case EgressDirect, EgressSelective, EgressFullTunnel, EgressIsolated:
	default:
		return fmt.Errorf("%w: unknown egress policy %q", ErrInvalid, p.Egress)
	}
	switch p.Ingress {
	case IngressDeny, IngressEstablished, IngressAllow:
	default:
		return fmt.Errorf("%w: unknown ingress policy %q", ErrInvalid, p.Ingress)
	}
	if p.FailMode != "closed" {
		return fmt.Errorf("%w: only fail-mode closed is supported", ErrInvalid)
	}
	if p.Egress == EgressSelective && len(p.EgressCIDRs) == 0 {
		return fmt.Errorf("%w: selective policy requires egress CIDRs", ErrInvalid)
	}
	if p.Egress == EgressFullTunnel && p.Exit == "" {
		return fmt.Errorf("%w: full-tunnel policy requires an exit", ErrInvalid)
	}
	if p.Egress != EgressFullTunnel && p.Exit != "" {
		return fmt.Errorf("%w: an exit is valid only for full-tunnel policy", ErrInvalid)
	}
	if p.Egress == EgressDirect && len(p.EgressCIDRs) != 0 {
		return fmt.Errorf("%w: direct policy cannot have tunnel CIDRs", ErrInvalid)
	}
	if p.Ingress == IngressAllow && len(p.IngressSources) == 0 {
		return fmt.Errorf("%w: allow ingress requires source CIDRs", ErrInvalid)
	}
	if p.Ingress != IngressAllow && len(p.IngressSources) != 0 {
		return fmt.Errorf("%w: ingress sources require allow ingress", ErrInvalid)
	}
	for _, prefix := range append(append([]netip.Prefix(nil), p.EgressCIDRs...), p.IngressSources...) {
		if !prefix.Addr().Is4() {
			return fmt.Errorf("%w: IPv6 is not supported in docker policy networks", ErrInvalid)
		}
		if prefix != prefix.Masked() {
			return fmt.Errorf("%w: non-canonical prefix %s", ErrInvalid, prefix)
		}
	}
	return nil
}

func flattenOptions(options map[string]any) map[string]string {
	result := make(map[string]string)
	var visit func(map[string]any)
	visit = func(values map[string]any) {
		for key, raw := range values {
			switch value := raw.(type) {
			case string:
				result[key] = strings.TrimSpace(value)
			case map[string]any:
				visit(value)
			}
		}
	}
	visit(options)
	return result
}

func parsePrefixes(value string) ([]netip.Prefix, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	seen := make(map[netip.Prefix]struct{})
	result := make([]netip.Prefix, 0)
	for _, item := range strings.Split(value, ",") {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(item))
		if err != nil {
			return nil, err
		}
		prefix = prefix.Masked()
		if _, ok := seen[prefix]; !ok {
			seen[prefix] = struct{}{}
			result = append(result, prefix)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].String() < result[j].String() })
	for i := range result {
		for j := i + 1; j < len(result); j++ {
			if result[i].Overlaps(result[j]) {
				return nil, fmt.Errorf("overlapping prefixes %s and %s", result[i], result[j])
			}
		}
	}
	return result, nil
}

func parseAddresses(value string) ([]netip.Addr, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	var result []netip.Addr
	for _, item := range strings.Split(value, ",") {
		addr, err := netip.ParseAddr(strings.TrimSpace(item))
		if err != nil {
			return nil, err
		}
		if !addr.Is4() {
			return nil, errors.New("IPv6 DNS is not supported")
		}
		result = append(result, addr)
	}
	return result, nil
}

// Authorization is a complete leased snapshot written by the authenticated
// Laneway control-plane client. Missing, expired, or partial authorization is
// rejected; the Docker request can never grant itself additional reachability.
type Authorization struct {
	Epoch            uint64         `json:"epoch"`
	ValidUntil       time.Time      `json:"valid_until"`
	ContainerSubnets []netip.Prefix `json:"container_subnets"`
	EgressCIDRs      []netip.Prefix `json:"egress_cidrs"`
	IngressSources   []netip.Prefix `json:"ingress_sources"`
	Exits            []string       `json:"exits"`
	BypassCIDRs      []netip.Prefix `json:"bypass_cidrs,omitempty"`
}

func (a Authorization) Authorize(now time.Time, subnet netip.Prefix, p Policy) error {
	if !a.ValidUntil.After(now) {
		return fmt.Errorf("%w: authorization lease is missing or expired", ErrUnauthorized)
	}
	if !prefixCovered(subnet, a.ContainerSubnets) {
		return fmt.Errorf("%w: container subnet %s", ErrUnauthorized, subnet)
	}
	for _, prefix := range p.EgressCIDRs {
		if !prefixCovered(prefix, a.EgressCIDRs) {
			return fmt.Errorf("%w: egress prefix %s", ErrUnauthorized, prefix)
		}
	}
	for _, prefix := range p.IngressSources {
		if !prefixCovered(prefix, a.IngressSources) {
			return fmt.Errorf("%w: ingress source %s", ErrUnauthorized, prefix)
		}
	}
	if p.Exit != "" {
		found := false
		for _, exit := range a.Exits {
			if exit == p.Exit {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%w: exit %q", ErrUnauthorized, p.Exit)
		}
	}
	return nil
}

func prefixCovered(want netip.Prefix, allowed []netip.Prefix) bool {
	for _, prefix := range allowed {
		if prefix.Contains(want.Addr()) && prefix.Bits() <= want.Bits() {
			return true
		}
	}
	return false
}
