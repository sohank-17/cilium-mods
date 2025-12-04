// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package payloadfilter

import (
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "map-payload-filter")

const (
	// MapName is the name of the payload filter map
	MapName = "cilium_payload_filter"

	// MaxEntries is the maximum number of entries in the map
	MaxEntries = 16384
)

// Key is the index into the payload filter map
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type Key struct {
	Identity uint32 `align:"identity"` // Security identity or namespace ID
}

// Value is the payload size limit in bytes
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type Value struct {
	MaxPayloadSize uint32 `align:"max_payload_size"`
}

// GetKeyPtr returns the unsafe pointer to the BPF key
func (k *Key) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

// GetValuePtr returns the unsafe pointer to the BPF value
func (v *Value) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

// String returns the key in human-readable format
func (k *Key) String() string { return fmt.Sprintf("identity=%d", k.Identity) }

// String returns the value in human-readable format
func (v *Value) String() string { return fmt.Sprintf("max_size=%d", v.MaxPayloadSize) }

// NewValue returns a new empty instance of the structure representing the BPF map value
func (k *Key) NewValue() bpf.MapValue { return &Value{} }

var (
	payloadFilterMap     *bpf.Map
	payloadFilterMapOnce = make(chan struct{})
)

// PayloadFilterMap returns the initialized payload filter map
func PayloadFilterMap() *bpf.Map {
	<-payloadFilterMapOnce
	return payloadFilterMap
}

func initPayloadFilterMap() {
	payloadFilterMap = bpf.NewMap(
		MapName,
		ebpf.Hash,
		&Key{},
		&Value{},
		MaxEntries,
		0,
	).WithCache().WithPressureMetric().
		WithEvents(option.Config.GetEventBufferConfig(MapName))

	if err := payloadFilterMap.OpenOrCreate(); err != nil {
		log.WithError(err).Fatal("Unable to open or create payload filter map")
	}

	close(payloadFilterMapOnce)
}

// Init initializes the payload filter map
func Init() {
	initPayloadFilterMap()
}

// UpdateLimit updates or adds a payload size limit for a given identity
func UpdateLimit(identity uint32, maxSize uint32) error {
	key := &Key{Identity: identity}
	value := &Value{MaxPayloadSize: maxSize}

	if err := payloadFilterMap.Update(key, value); err != nil {
		return fmt.Errorf("failed to update payload limit: %w", err)
	}

	log.WithFields(map[string]interface{}{
		"identity": identity,
		"maxSize":  maxSize,
	}).Debug("Updated payload filter limit")

	return nil
}

// DeleteLimit removes a payload size limit for a given identity
func DeleteLimit(identity uint32) error {
	key := &Key{Identity: identity}

	if err := payloadFilterMap.Delete(key); err != nil {
		return fmt.Errorf("failed to delete payload limit: %w", err)
	}

	log.WithFields(map[string]interface{}{
		"identity": identity,
	}).Debug("Deleted payload filter limit")

	return nil
}

// GetLimit retrieves the payload size limit for a given identity
func GetLimit(identity uint32) (uint32, error) {
	key := &Key{Identity: identity}
	value := &Value{}

	if err := payloadFilterMap.Lookup(key, value); err != nil {
		return 0, fmt.Errorf("failed to lookup payload limit: %w", err)
	}

	return value.MaxPayloadSize, nil
}

// Cleanup removes all entries from the payload filter map
func Cleanup() error {
	if payloadFilterMap != nil {
		return payloadFilterMap.DeleteAll()
	}
	return nil
}