// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dnsfilter

import (
	"fmt"
	"hash/fnv"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "map-dns-filter")

const (
	// MapName is the name of the DNS filter map
	MapName = "cilium_dns_filter"

	// MaxEntries is the maximum number of entries in the map
	MaxEntries = 16384
)

// Key is the index into the DNS filter map
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type Key struct {
	Identity   uint32 `align:"identity"`    // Security identity
	DomainHash uint32 `align:"domain_hash"` // Hash of the domain name
}

// Value represents the action to take for a domain
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type Value struct {
	Action uint8 `align:"action"` // 0 = allow, 1 = block
}

// GetKeyPtr returns the unsafe pointer to the BPF key
func (k *Key) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

// GetValuePtr returns the unsafe pointer to the BPF value
func (v *Value) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

// String returns the key in human-readable format
func (k *Key) String() string {
	return fmt.Sprintf("identity=%d domain_hash=%d", k.Identity, k.DomainHash)
}

// String returns the value in human-readable format
func (v *Value) String() string {
	action := "allow"
	if v.Action == 1 {
		action = "block"
	}
	return fmt.Sprintf("action=%s", action)
}

// NewValue returns a new empty instance of the structure representing the BPF map value
func (k *Key) NewValue() bpf.MapValue { return &Value{} }

var (
	dnsFilterMap     *bpf.Map
	dnsFilterMapOnce = make(chan struct{})
)

// DNSFilterMap returns the initialized DNS filter map
func DNSFilterMap() *bpf.Map {
	<-dnsFilterMapOnce
	return dnsFilterMap
}

func initDNSFilterMap() {
	dnsFilterMap = bpf.NewMap(
		MapName,
		ebpf.Hash,
		&Key{},
		&Value{},
		MaxEntries,
		0,
	).WithCache().WithPressureMetric().
		WithEvents(option.Config.GetEventBufferConfig(MapName))

	if err := dnsFilterMap.OpenOrCreate(); err != nil {
		log.WithError(err).Fatal("Unable to open or create DNS filter map")
	}

	close(dnsFilterMapOnce)
}

// Init initializes the DNS filter map
func Init() {
	initDNSFilterMap()
}

// hashDomain computes a hash for a domain name
// Uses DJB2 hash algorithm to match the eBPF implementation
func hashDomain(domain string) uint32 {
	hash := uint32(5381)
	for i := 0; i < len(domain); i++ {
		hash = ((hash << 5) + hash) + uint32(domain[i])
	}
	return hash
}

// normalizeDomain normalizes a domain name (lowercase, trim)
func normalizeDomain(domain string) string {
	return strings.ToLower(strings.TrimSpace(domain))
}

// BlockDomain adds a domain to the block list for a given identity
func BlockDomain(identity uint32, domain string) error {
	domain = normalizeDomain(domain)
	domainHash := hashDomain(domain)

	key := &Key{
		Identity:   identity,
		DomainHash: domainHash,
	}
	value := &Value{Action: 1} // 1 = block

	if err := dnsFilterMap.Update(key, value); err != nil {
		return fmt.Errorf("failed to block domain: %w", err)
	}

	log.WithFields(map[string]interface{}{
		"identity": identity,
		"domain":   domain,
		"hash":     domainHash,
	}).Debug("Blocked DNS domain")

	return nil
}

// AllowDomain removes a domain from the block list for a given identity
func AllowDomain(identity uint32, domain string) error {
	domain = normalizeDomain(domain)
	domainHash := hashDomain(domain)

	key := &Key{
		Identity:   identity,
		DomainHash: domainHash,
	}

	if err := dnsFilterMap.Delete(key); err != nil {
		return fmt.Errorf("failed to allow domain: %w", err)
	}

	log.WithFields(map[string]interface{}{
		"identity": identity,
		"domain":   domain,
		"hash":     domainHash,
	}).Debug("Allowed DNS domain")

	return nil
}

// IsBlocked checks if a domain is blocked for a given identity
func IsBlocked(identity uint32, domain string) (bool, error) {
	domain = normalizeDomain(domain)
	domainHash := hashDomain(domain)

	key := &Key{
		Identity:   identity,
		DomainHash: domainHash,
	}
	value := &Value{}

	if err := dnsFilterMap.Lookup(key, value); err != nil {
		// Not found means not blocked
		return false, nil
	}

	return value.Action == 1, nil
}

// BlockDomains adds multiple domains to the block list
func BlockDomains(identity uint32, domains []string) error {
	for _, domain := range domains {
		if err := BlockDomain(identity, domain); err != nil {
			return err
		}
	}
	return nil
}

// GetBlockedDomains returns all blocked domain hashes for an identity
// Note: Cannot retrieve original domain names from hashes
func GetBlockedDomains(identity uint32) ([]uint32, error) {
	var blockedHashes []uint32

	// Iterate through the map (this is a simplified version)
	// In practice, you'd need to iterate through all keys
	// This is a placeholder for the iteration logic

	return blockedHashes, nil
}

// Cleanup removes all entries from the DNS filter map
func Cleanup() error {
	if dnsFilterMap != nil {
		return dnsFilterMap.DeleteAll()
	}
	return nil
}

// ParseWildcardDomain handles wildcard domain patterns like "*.example.com"
func ParseWildcardDomain(domain string) (string, bool) {
	domain = normalizeDomain(domain)
	if strings.HasPrefix(domain, "*.") {
		return domain[2:], true // Return domain without "*."
	}
	return domain, false
}

// BlockWildcardDomain blocks a wildcard domain pattern
// For wildcard patterns, we store the base domain
func BlockWildcardDomain(identity uint32, pattern string) error {
	baseDomain, isWildcard := ParseWildcardDomain(pattern)
	
	if isWildcard {
		// Store the wildcard pattern itself
		return BlockDomain(identity, pattern)
	}
	
	return BlockDomain(identity, baseDomain)
}