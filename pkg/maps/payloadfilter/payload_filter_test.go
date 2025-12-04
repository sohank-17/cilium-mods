// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package payloadfilter

import (
	"testing"

	. "gopkg.in/check.v1"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/testutils"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type PayloadFilterTestSuite struct{}

var _ = Suite(&PayloadFilterTestSuite{})

func (s *PayloadFilterTestSuite) SetUpSuite(c *C) {
	testutils.PrivilegedTest(c)
	bpf.CheckOrMountFS("")
}

func (s *PayloadFilterTestSuite) SetUpTest(c *C) {
	// Initialize the map for each test
	Init()
}

func (s *PayloadFilterTestSuite) TearDownTest(c *C) {
	// Clean up after each test
	err := Cleanup()
	c.Assert(err, IsNil)
}

// TestUpdateAndGetLimit tests adding and retrieving a payload limit
func (s *PayloadFilterTestSuite) TestUpdateAndGetLimit(c *C) {
	identity := uint32(12345)
	maxSize := uint32(1048576) // 1MB

	// Update the limit
	err := UpdateLimit(identity, maxSize)
	c.Assert(err, IsNil)

	// Retrieve the limit
	retrievedSize, err := GetLimit(identity)
	c.Assert(err, IsNil)
	c.Assert(retrievedSize, Equals, maxSize)
}

// TestUpdateExistingLimit tests updating an existing limit
func (s *PayloadFilterTestSuite) TestUpdateExistingLimit(c *C) {
	identity := uint32(12345)
	initialSize := uint32(1048576)  // 1MB
	updatedSize := uint32(2097152)  // 2MB

	// Set initial limit
	err := UpdateLimit(identity, initialSize)
	c.Assert(err, IsNil)

	// Update the limit
	err = UpdateLimit(identity, updatedSize)
	c.Assert(err, IsNil)

	// Verify the update
	retrievedSize, err := GetLimit(identity)
	c.Assert(err, IsNil)
	c.Assert(retrievedSize, Equals, updatedSize)
}

// TestDeleteLimit tests removing a payload limit
func (s *PayloadFilterTestSuite) TestDeleteLimit(c *C) {
	identity := uint32(12345)
	maxSize := uint32(1048576)

	// Add a limit
	err := UpdateLimit(identity, maxSize)
	c.Assert(err, IsNil)

	// Delete the limit
	err = DeleteLimit(identity)
	c.Assert(err, IsNil)

	// Verify it's deleted
	_, err = GetLimit(identity)
	c.Assert(err, NotNil) // Should return error for non-existent entry
}

// TestDeleteNonExistentLimit tests deleting a non-existent limit
func (s *PayloadFilterTestSuite) TestDeleteNonExistentLimit(c *C) {
	identity := uint32(99999)

	// Try to delete non-existent entry
	err := DeleteLimit(identity)
	c.Assert(err, NotNil)
}

// TestGetNonExistentLimit tests retrieving a non-existent limit
func (s *PayloadFilterTestSuite) TestGetNonExistentLimit(c *C) {
	identity := uint32(99999)

	_, err := GetLimit(identity)
	c.Assert(err, NotNil)
}

// TestMultipleIdentities tests managing multiple identities
func (s *PayloadFilterTestSuite) TestMultipleIdentities(c *C) {
	identities := []struct {
		id   uint32
		size uint32
	}{
		{12345, 1048576},  // 1MB
		{23456, 2097152},  // 2MB
		{34567, 524288},   // 512KB
	}

	// Add all limits
	for _, entry := range identities {
		err := UpdateLimit(entry.id, entry.size)
		c.Assert(err, IsNil)
	}

	// Verify all limits
	for _, entry := range identities {
		size, err := GetLimit(entry.id)
		c.Assert(err, IsNil)
		c.Assert(size, Equals, entry.size)
	}
}

// TestZeroSizeLimit tests setting a zero-byte limit
func (s *PayloadFilterTestSuite) TestZeroSizeLimit(c *C) {
	identity := uint32(12345)
	zeroSize := uint32(0)

	err := UpdateLimit(identity, zeroSize)
	c.Assert(err, IsNil)

	size, err := GetLimit(identity)
	c.Assert(err, IsNil)
	c.Assert(size, Equals, zeroSize)
}

// TestMaxSizeLimit tests setting a very large limit
func (s *PayloadFilterTestSuite) TestMaxSizeLimit(c *C) {
	identity := uint32(12345)
	maxSize := uint32(4294967295) // Max uint32

	err := UpdateLimit(identity, maxSize)
	c.Assert(err, IsNil)

	size, err := GetLimit(identity)
	c.Assert(err, IsNil)
	c.Assert(size, Equals, maxSize)
}

// TestCleanup tests cleaning up all entries
func (s *PayloadFilterTestSuite) TestCleanup(c *C) {
	// Add multiple entries
	for i := uint32(1); i <= 10; i++ {
		err := UpdateLimit(i*1000, i*1048576)
		c.Assert(err, IsNil)
	}

	// Cleanup all
	err := Cleanup()
	c.Assert(err, IsNil)

	// Verify all are deleted
	for i := uint32(1); i <= 10; i++ {
		_, err := GetLimit(i * 1000)
		c.Assert(err, NotNil)
	}
}

// TestKeyStringRepresentation tests the String() method of Key
func (s *PayloadFilterTestSuite) TestKeyStringRepresentation(c *C) {
	key := &Key{Identity: 12345}
	expected := "identity=12345"
	c.Assert(key.String(), Equals, expected)
}

// TestValueStringRepresentation tests the String() method of Value
func (s *PayloadFilterTestSuite) TestValueStringRepresentation(c *C) {
	value := &Value{MaxPayloadSize: 1048576}
	expected := "max_size=1048576"
	c.Assert(value.String(), Equals, expected)
}