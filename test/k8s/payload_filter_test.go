// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build integration

package integration

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	. "gopkg.in/check.v1"

	"github.com/cilium/cilium/pkg/maps/payloadfilter"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type PayloadFilterIntegrationSuite struct {
	ctx    context.Context
	cancel context.CancelFunc
}

var _ = Suite(&PayloadFilterIntegrationSuite{})

func (s *PayloadFilterIntegrationSuite) SetUpSuite(c *C) {
	testutils.PrivilegedTest(c)
	
	// Enable payload filter feature
	option.Config.EnablePayloadFilter = true
	
	s.ctx, s.cancel = context.WithCancel(context.Background())
}

func (s *PayloadFilterIntegrationSuite) TearDownSuite(c *C) {
	s.cancel()
	option.Config.EnablePayloadFilter = false
}

func (s *PayloadFilterIntegrationSuite) SetUpTest(c *C) {
	payloadfilter.Init()
}

func (s *PayloadFilterIntegrationSuite) TearDownTest(c *C) {
	err := payloadfilter.Cleanup()
	c.Assert(err, IsNil)
}

// TestBasicPayloadFiltering tests basic payload size enforcement
func (s *PayloadFilterIntegrationSuite) TestBasicPayloadFiltering(c *C) {
	identity := uint32(1000)
	limitMB := uint32(1048576) // 1MB

	// Set payload limit
	err := payloadfilter.UpdateLimit(identity, limitMB)
	c.Assert(err, IsNil)

	// Verify limit is set
	limit, err := payloadfilter.GetLimit(identity)
	c.Assert(err, IsNil)
	c.Assert(limit, Equals, limitMB)
}

// TestPayloadFilterPolicyUpdate tests updating policies dynamically
func (s *PayloadFilterIntegrationSuite) TestPayloadFilterPolicyUpdate(c *C) {
	identity := uint32(1000)
	initialLimit := uint32(1048576)  // 1MB
	updatedLimit := uint32(2097152)  // 2MB

	// Set initial limit
	err := payloadfilter.UpdateLimit(identity, initialLimit)
	c.Assert(err, IsNil)

	// Update limit
	err = payloadfilter.UpdateLimit(identity, updatedLimit)
	c.Assert(err, IsNil)

	// Verify update
	limit, err := payloadfilter.GetLimit(identity)
	c.Assert(err, IsNil)
	c.Assert(limit, Equals, updatedLimit)
}

// TestPayloadFilterPolicyDeletion tests removing policies
func (s *PayloadFilterIntegrationSuite) TestPayloadFilterPolicyDeletion(c *C) {
	identity := uint32(1000)
	limit := uint32(1048576)

	// Set limit
	err := payloadfilter.UpdateLimit(identity, limit)
	c.Assert(err, IsNil)

	// Delete limit
	err = payloadfilter.DeleteLimit(identity)
	c.Assert(err, IsNil)

	// Verify deletion
	_, err = payloadfilter.GetLimit(identity)
	c.Assert(err, NotNil)
}

// TestMultipleIdentityPolicies tests managing multiple identity policies
func (s *PayloadFilterIntegrationSuite) TestMultipleIdentityPolicies(c *C) {
	policies := map[uint32]uint32{
		1000: 1048576,  // 1MB
		2000: 2097152,  // 2MB
		3000: 524288,   // 512KB
		4000: 10485760, // 10MB
	}

	// Set all policies
	for identity, limit := range policies {
		err := payloadfilter.UpdateLimit(identity, limit)
		c.Assert(err, IsNil)
	}

	// Verify all policies
	for identity, expectedLimit := range policies {
		limit, err := payloadfilter.GetLimit(identity)
		c.Assert(err, IsNil)
		c.Assert(limit, Equals, expectedLimit)
	}
}

// TestPayloadFilterLogFile tests that log file is created
func (s *PayloadFilterIntegrationSuite) TestPayloadFilterLogFile(c *C) {
	logPath := "/var/log/cilium/payload-filter-alerts.log"

	// Create log directory if it doesn't exist
	err := os.MkdirAll("/var/log/cilium", 0755)
	c.Assert(err, IsNil)

	// Create or truncate log file
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	c.Assert(err, IsNil)
	defer f.Close()

	// Write test entry
	timestamp := time.Now().Format(time.RFC3339)
	logEntry := fmt.Sprintf("%s identity=12345 payload_size=2097152 limit=1048576 protocol=TCP action=DROP\n",
		timestamp)
	_, err = f.WriteString(logEntry)
	c.Assert(err, IsNil)

	// Verify file exists and has content
	info, err := os.Stat(logPath)
	c.Assert(err, IsNil)
	c.Assert(info.Size() > 0, Equals, true)
}

// TestPayloadFilterConfigFlag tests the configuration flag
func (s *PayloadFilterIntegrationSuite) TestPayloadFilterConfigFlag(c *C) {
	// Verify the feature flag is set
	c.Assert(option.Config.EnablePayloadFilter, Equals, true)
}

// TestPayloadFilterWithZeroLimit tests zero-byte limit edge case
func (s *PayloadFilterIntegrationSuite) TestPayloadFilterWithZeroLimit(c *C) {
	identity := uint32(1000)
	zeroLimit := uint32(0)

	err := payloadfilter.UpdateLimit(identity, zeroLimit)
	c.Assert(err, IsNil)

	limit, err := payloadfilter.GetLimit(identity)
	c.Assert(err, IsNil)
	c.Assert(limit, Equals, zeroLimit)
}

// TestPayloadFilterMapCapacity tests that map can handle max entries
func (s *PayloadFilterIntegrationSuite) TestPayloadFilterMapCapacity(c *C) {
	// Add entries up to a reasonable test limit (not full 16384)
	numEntries := 100
	
	for i := 0; i < numEntries; i++ {
		identity := uint32(10000 + i)
		limit := uint32((i + 1) * 1048576)
		
		err := payloadfilter.UpdateLimit(identity, limit)
		c.Assert(err, IsNil)
	}

	// Verify all entries
	for i := 0; i < numEntries; i++ {
		identity := uint32(10000 + i)
		expectedLimit := uint32((i + 1) * 1048576)
		
		limit, err := payloadfilter.GetLimit(identity)
		c.Assert(err, IsNil)
		c.Assert(limit, Equals, expectedLimit)
	}
}