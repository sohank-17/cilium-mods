// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dnsfilter

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

type DNSFilterTestSuite struct{}

var _ = Suite(&DNSFilterTestSuite{})

func (s *DNSFilterTestSuite) SetUpSuite(c *C) {
	testutils.PrivilegedTest(c)
	bpf.CheckOrMountFS("")
}

func (s *DNSFilterTestSuite) SetUpTest(c *C) {
	// Initialize the map for each test
	Init()
}

func (s *DNSFilterTestSuite) TearDownTest(c *C) {
	// Clean up after each test
	err := Cleanup()
	c.Assert(err, IsNil)
}

// TestBlockAndCheckDomain tests blocking a domain
func (s *DNSFilterTestSuite) TestBlockAndCheckDomain(c *C) {
	identity := uint32(12345)
	domain := "facebook.com"

	// Block the domain
	err := BlockDomain(identity, domain)
	c.Assert(err, IsNil)

	// Check if blocked
	blocked, err := IsBlocked(identity, domain)
	c.Assert(err, IsNil)
	c.Assert(blocked, Equals, true)
}

// TestAllowDomain tests allowing a previously blocked domain
func (s *DNSFilterTestSuite) TestAllowDomain(c *C) {
	identity := uint32(12345)
	domain := "facebook.com"

	// Block the domain
	err := BlockDomain(identity, domain)
	c.Assert(err, IsNil)

	// Allow the domain
	err = AllowDomain(identity, domain)
	c.Assert(err, IsNil)

	// Check if still blocked
	blocked, err := IsBlocked(identity, domain)
	c.Assert(err, IsNil)
	c.Assert(blocked, Equals, false)
}

// TestDomainNotBlocked tests checking a non-blocked domain
func (s *DNSFilterTestSuite) TestDomainNotBlocked(c *C) {
	identity := uint32(12345)
	domain := "example.com"

	// Check domain that was never blocked
	blocked, err := IsBlocked(identity, domain)
	c.Assert(err, IsNil)
	c.Assert(blocked, Equals, false)
}

// TestMultipleDomains tests blocking multiple domains
func (s *DNSFilterTestSuite) TestMultipleDomains(c *C) {
	identity := uint32(12345)
	domains := []string{
		"facebook.com",
		"twitter.com",
		"instagram.com",
		"dropbox.com",
	}

	// Block all domains
	err := BlockDomains(identity, domains)
	c.Assert(err, IsNil)

	// Verify all are blocked
	for _, domain := range domains {
		blocked, err := IsBlocked(identity, domain)
		c.Assert(err, IsNil)
		c.Assert(blocked, Equals, true)
	}
}

// TestMultipleIdentities tests blocking domains for different identities
func (s *DNSFilterTestSuite) TestMultipleIdentities(c *C) {
	identity1 := uint32(12345)
	identity2 := uint32(23456)
	domain := "facebook.com"

	// Block for identity1
	err := BlockDomain(identity1, domain)
	c.Assert(err, IsNil)

	// Check identity1
	blocked, err := IsBlocked(identity1, domain)
	c.Assert(err, IsNil)
	c.Assert(blocked, Equals, true)

	// Check identity2 (should not be blocked)
	blocked, err = IsBlocked(identity2, domain)
	c.Assert(err, IsNil)
	c.Assert(blocked, Equals, false)

	// Block for identity2
	err = BlockDomain(identity2, domain)
	c.Assert(err, IsNil)

	// Check identity2 again
	blocked, err = IsBlocked(identity2, domain)
	c.Assert(err, IsNil)
	c.Assert(blocked, Equals, true)
}

// TestDomainNormalization tests that domains are normalized
func (s *DNSFilterTestSuite) TestDomainNormalization(c *C) {
	identity := uint32(12345)

	// Block with uppercase
	err := BlockDomain(identity, "FACEBOOK.COM")
	c.Assert(err, IsNil)

	// Check with lowercase
	blocked, err := IsBlocked(identity, "facebook.com")
	c.Assert(err, IsNil)
	c.Assert(blocked, Equals, true)

	// Check with mixed case
	blocked, err = IsBlocked(identity, "FaceBook.Com")
	c.Assert(err, IsNil)
	c.Assert(blocked, Equals, true)
}

// TestDomainWithSpaces tests trimming spaces
func (s *DNSFilterTestSuite) TestDomainWithSpaces(c *C) {
	identity := uint32(12345)

	// Block with spaces
	err := BlockDomain(identity, "  facebook.com  ")
	c.Assert(err, IsNil)

	// Check without spaces
	blocked, err := IsBlocked(identity, "facebook.com")
	c.Assert(err, IsNil)
	c.Assert(blocked, Equals, true)
}

// TestHashDomain tests the domain hashing function
func (s *DNSFilterTestSuite) TestHashDomain(c *C) {
	domain1 := "facebook.com"
	domain2 := "facebook.com"
	domain3 := "twitter.com"

	hash1 := hashDomain(domain1)
	hash2 := hashDomain(domain2)
	hash3 := hashDomain(domain3)

	// Same domains should produce same hash
	c.Assert(hash1, Equals, hash2)

	// Different domains should produce different hashes
	c.Assert(hash1, Not(Equals), hash3)
}

// TestWildcardDomain tests wildcard domain patterns
func (s *DNSFilterTestSuite) TestWildcardDomain(c *C) {
	identity := uint32(12345)
	pattern := "*.facebook.com"

	// Block wildcard pattern
	err := BlockWildcardDomain(identity, pattern)
	c.Assert(err, IsNil)

	// Check if the pattern itself is blocked
	blocked, err := IsBlocked(identity, pattern)
	c.Assert(err, IsNil)
	c.Assert(blocked, Equals, true)
}

// TestParseWildcardDomain tests wildcard parsing
func (s *DNSFilterTestSuite) TestParseWildcardDomain(c *C) {
	// Test wildcard pattern
	baseDomain, isWildcard := ParseWildcardDomain("*.facebook.com")
	c.Assert(isWildcard, Equals, true)
	c.Assert(baseDomain, Equals, "facebook.com")

	// Test non-wildcard
	baseDomain, isWildcard = ParseWildcardDomain("facebook.com")
	c.Assert(isWildcard, Equals, false)
	c.Assert(baseDomain, Equals, "facebook.com")
}

// TestSubdomains tests blocking subdomains
func (s *DNSFilterTestSuite) TestSubdomains(c *C) {
	identity := uint32(12345)

	// Block specific subdomain
	err := BlockDomain(identity, "api.facebook.com")
	c.Assert(err, IsNil)

	// Check subdomain
	blocked, err := IsBlocked(identity, "api.facebook.com")
	c.Assert(err, IsNil)
	c.Assert(blocked, Equals, true)

	// Check main domain (should not be blocked)
	blocked, err = IsBlocked(identity, "facebook.com")
	c.Assert(err, IsNil)
	c.Assert(blocked, Equals, false)
}

// TestKeyStringRepresentation tests the String() method of Key
func (s *DNSFilterTestSuite) TestKeyStringRepresentation(c *C) {
	key := &Key{Identity: 12345, DomainHash: 98765}
	expected := "identity=12345 domain_hash=98765"
	c.Assert(key.String(), Equals, expected)
}

// TestValueStringRepresentation tests the String() method of Value
func (s *DNSFilterTestSuite) TestValueStringRepresentation(c *C) {
	// Block action
	value := &Value{Action: 1}
	c.Assert(value.String(), Equals, "action=block")

	// Allow action
	value = &Value{Action: 0}
	c.Assert(value.String(), Equals, "action=allow")
}

// TestBlockMultipleSubdomains tests blocking multiple subdomains
func (s *DNSFilterTestSuite) TestBlockMultipleSubdomains(c *C) {
	identity := uint32(12345)
	domains := []string{
		"www.facebook.com",
		"api.facebook.com",
		"m.facebook.com",
		"graph.facebook.com",
	}

	// Block all subdomains
	err := BlockDomains(identity, domains)
	c.Assert(err, IsNil)

	// Verify all are blocked
	for _, domain := range domains {
		blocked, err := IsBlocked(identity, domain)
		c.Assert(err, IsNil)
		c.Assert(blocked, Equals, true)
	}
}

// TestCleanup tests cleaning up all entries
func (s *DNSFilterTestSuite) TestCleanup(c *C) {
	identity := uint32(12345)
	domains := []string{
		"facebook.com",
		"twitter.com",
		"instagram.com",
	}

	// Block multiple domains
	err := BlockDomains(identity, domains)
	c.Assert(err, IsNil)

	// Cleanup all
	err = Cleanup()
	c.Assert(err, IsNil)

	// Verify all are removed
	for _, domain := range domains {
		blocked, err := IsBlocked(identity, domain)
		c.Assert(err, IsNil)
		c.Assert(blocked, Equals, false)
	}
}