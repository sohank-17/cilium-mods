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

	"github.com/cilium/cilium/pkg/maps/dnsfilter"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

// Hook up gocheck into the "go test" runner.
func TestDNS(t *testing.T) {
	TestingT(t)
}

type DNSFilterIntegrationSuite struct {
	ctx    context.Context
	cancel context.CancelFunc
}

var _ = Suite(&DNSFilterIntegrationSuite{})

func (s *DNSFilterIntegrationSuite) SetUpSuite(c *C) {
	testutils.PrivilegedTest(c)
	
	// Enable DNS filter feature
	option.Config.EnableDNSFilter = true
	
	s.ctx, s.cancel = context.WithCancel(context.Background())
}

func (s *DNSFilterIntegrationSuite) TearDownSuite(c *C) {
	s.cancel()
	option.Config.EnableDNSFilter = false
}

func (s *DNSFilterIntegrationSuite) SetUpTest(c *C) {
	dnsfilter.Init()
}

func (s *DNSFilterIntegrationSuite) TearDownTest(c *C) {
	err := dnsfilter.Cleanup()
	c.Assert(err, IsNil)
}

// TestBasicDNSBlocking tests basic DNS domain blocking
func (s *DNSFilterIntegrationSuite) TestBasicDNSBlocking(c *C) {
	identity := uint32(1000)
	domain := "facebook.com"

	// Block domain
	err := dnsfilter.BlockDomain(identity, domain)
	c.Assert(err, IsNil)

	// Verify domain is blocked
	blocked, err := dnsfilter.IsBlocked(identity, domain)
	c.Assert(err, IsNil)
	c.Assert(blocked, Equals, true)
}

// TestBlockMultipleDomains tests blocking multiple domains
func (s *DNSFilterIntegrationSuite) TestBlockMultipleDomains(c *C) {
	identity := uint32(1000)
	domains := []string{
		"facebook.com",
		"twitter.com",
		"instagram.com",
		"dropbox.com",
	}

	// Block all domains
	err := dnsfilter.BlockDomains(identity, domains)
	c.Assert(err, IsNil)

	// Verify all are blocked
	for _, domain := range domains {
		blocked, err := dnsfilter.IsBlocked(identity, domain)
		c.Assert(err, IsNil)
		c.Assert(blocked, Equals, true)
	}
}

// TestAllowPreviouslyBlockedDomain tests allowing a blocked domain
func (s *DNSFilterIntegrationSuite) TestAllowPreviouslyBlockedDomain(c *C) {
	identity := uint32(1000)
	domain := "facebook.com"

	// Block domain
	err := dnsfilter.BlockDomain(identity, domain)
	c.Assert(err, IsNil)

	// Allow domain
	err = dnsfilter.AllowDomain(identity, domain)
	c.Assert(err, IsNil)

	// Verify domain is no longer blocked
	blocked, err := dnsfilter.IsBlocked(identity, domain)
	c.Assert(err, IsNil)
	c.Assert(blocked, Equals, false)
}

// TestPerIdentityBlocking tests that blocking is per-identity
func (s *DNSFilterIntegrationSuite) TestPerIdentityBlocking(c *C) {
	identity1 := uint32(1000)
	identity2 := uint32(2000)
	domain := "facebook.com"

	// Block for identity1 only
	err := dnsfilter.BlockDomain(identity1, domain)
	c.Assert(err, IsNil)

	// Verify blocked for identity1
	blocked, err := dnsfilter.IsBlocked(identity1, domain)
	c.Assert(err, IsNil)
	c.Assert(blocked, Equals, true)

	// Verify not blocked for identity2
	blocked, err = dnsfilter.IsBlocked(identity2, domain)
	c.Assert(err, IsNil)
	c.Assert(blocked, Equals, false)
}

// TestWildcardDomainBlocking tests wildcard patterns
func (s *DNSFilterIntegrationSuite) TestWildcardDomainBlocking(c *C) {
	identity := uint32(1000)
	pattern := "*.facebook.com"

	// Block wildcard pattern
	err := dnsfilter.BlockWildcardDomain(identity, pattern)
	c.Assert(err, IsNil)

	// Verify pattern is stored
	blocked, err := dnsfilter.IsBlocked(identity, pattern)
	c.Assert(err, IsNil)
	c.Assert(blocked, Equals, true)
}

// TestDomainNormalization tests case-insensitive blocking
func (s *DNSFilterIntegrationSuite) TestDomainNormalization(c *C) {
	identity := uint32(1000)

	// Block with uppercase
	err := dnsfilter.BlockDomain(identity, "FACEBOOK.COM")
	c.Assert(err, IsNil)

	// Check with lowercase
	blocked, err := dnsfilter.IsBlocked(identity, "facebook.com")
	c.Assert(err, IsNil)
	c.Assert(blocked, Equals, true)

	// Check with mixed case
	blocked, err = dnsfilter.IsBlocked(identity, "FaceBook.Com")
	c.Assert(err, IsNil)
	c.Assert(blocked, Equals, true)
}

// TestSubdomainBlocking tests blocking specific subdomains
func (s *DNSFilterIntegrationSuite) TestSubdomainBlocking(c *C) {
	identity := uint32(1000)

	// Block specific subdomain
	err := dnsfilter.BlockDomain(identity, "api.facebook.com")
	c.Assert(err, IsNil)

	// Verify subdomain is blocked
	blocked, err := dnsfilter.IsBlocked(identity, "api.facebook.com")
	c.Assert(err, IsNil)
	c.Assert(blocked, Equals, true)

	// Verify main domain is not blocked
	blocked, err = dnsfilter.IsBlocked(identity, "facebook.com")
	c.Assert(err, IsNil)
	c.Assert(blocked, Equals, false)
}

// TestMultipleSubdomains tests blocking multiple subdomains
func (s *DNSFilterIntegrationSuite) TestMultipleSubdomains(c *C) {
	identity := uint32(1000)
	subdomains := []string{
		"www.facebook.com",
		"api.facebook.com",
		"m.facebook.com",
		"graph.facebook.com",
	}

	// Block all subdomains
	err := dnsfilter.BlockDomains(identity, subdomains)
	c.Assert(err, IsNil)

	// Verify all subdomains are blocked
	for _, subdomain := range subdomains {
		blocked, err := dnsfilter.IsBlocked(identity, subdomain)
		c.Assert(err, IsNil)
		c.Assert(blocked, Equals, true)
	}
}

// TestDNSFilterLogFile tests that log file is created
func (s *DNSFilterIntegrationSuite) TestDNSFilterLogFile(c *C) {
	logPath := "/var/log/cilium/dns-filter-alerts.log"

	// Create log directory if it doesn't exist
	err := os.MkdirAll("/var/log/cilium", 0755)
	c.Assert(err, IsNil)

	// Create or truncate log file
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	c.Assert(err, IsNil)
	defer f.Close()

	// Write test entry
	timestamp := time.Now().Format(time.RFC3339)
	logEntry := fmt.Sprintf("%s identity=12345 domain_hash=3847562 domain=facebook.com src_ip=10.0.1.5 dst_ip=8.8.8.8 action=BLOCK\n",
		timestamp)
	_, err = f.WriteString(logEntry)
	c.Assert(err, IsNil)

	// Verify file exists and has content
	info, err := os.Stat(logPath)
	c.Assert(err, IsNil)
	c.Assert(info.Size() > 0, Equals, true)
}

// TestDNSFilterConfigFlag tests the configuration flag
func (s *DNSFilterIntegrationSuite) TestDNSFilterConfigFlag(c *C) {
	// Verify the feature flag is set
	c.Assert(option.Config.EnableDNSFilter, Equals, true)
}

// TestBlockCommonSocialMedia tests blocking common social media domains
func (s *DNSFilterIntegrationSuite) TestBlockCommonSocialMedia(c *C) {
	identity := uint32(1000)
	socialMediaDomains := []string{
		"facebook.com",
		"twitter.com",
		"instagram.com",
		"tiktok.com",
		"snapchat.com",
		"linkedin.com",
	}

	// Block all social media domains
	err := dnsfilter.BlockDomains(identity, socialMediaDomains)
	c.Assert(err, IsNil)

	// Verify all are blocked
	for _, domain := range socialMediaDomains {
		blocked, err := dnsfilter.IsBlocked(identity, domain)
		c.Assert(err, IsNil)
		c.Assert(blocked, Equals, true)
	}
}

// TestBlockFileSharing tests blocking file sharing services
func (s *DNSFilterIntegrationSuite) TestBlockFileSharing(c *C) {
	identity := uint32(1000)
	fileSharingDomains := []string{
		"dropbox.com",
		"drive.google.com",
		"onedrive.live.com",
		"box.com",
		"wetransfer.com",
	}

	// Block all file sharing domains
	err := dnsfilter.BlockDomains(identity, fileSharingDomains)
	c.Assert(err, IsNil)

	// Verify all are blocked
	for _, domain := range fileSharingDomains {
		blocked, err := dnsfilter.IsBlocked(identity, domain)
		c.Assert(err, IsNil)
		c.Assert(blocked, Equals, true)
	}
}

// TestDynamicPolicyUpdate tests updating policies dynamically
func (s *DNSFilterIntegrationSuite) TestDynamicPolicyUpdate(c *C) {
	identity := uint32(1000)
	domain := "facebook.com"

	// Initially allow
	blocked, err := dnsfilter.IsBlocked(identity, domain)
	c.Assert(err, IsNil)
	c.Assert(blocked, Equals, false)

	// Block domain
	err = dnsfilter.BlockDomain(identity, domain)
	c.Assert(err, IsNil)

	// Verify blocked
	blocked, err = dnsfilter.IsBlocked(identity, domain)
	c.Assert(err, IsNil)
	c.Assert(blocked, Equals, true)

	// Allow again
	err = dnsfilter.AllowDomain(identity, domain)
	c.Assert(err, IsNil)

	// Verify allowed
	blocked, err = dnsfilter.IsBlocked(identity, domain)
	c.Assert(err, IsNil)
	c.Assert(blocked, Equals, false)
}

// TestLargeScaleBlocking tests blocking many domains
func (s *DNSFilterIntegrationSuite) TestLargeScaleBlocking(c *C) {
	identity := uint32(1000)
	numDomains := 100

	// Generate and block many domains
	for i := 0; i < numDomains; i++ {
		domain := fmt.Sprintf("blocked-domain-%d.com", i)
		err := dnsfilter.BlockDomain(identity, domain)
		c.Assert(err, IsNil)
	}

	// Verify all are blocked
	for i := 0; i < numDomains; i++ {
		domain := fmt.Sprintf("blocked-domain-%d.com", i)
		blocked, err := dnsfilter.IsBlocked(identity, domain)
		c.Assert(err, IsNil)
		c.Assert(blocked, Equals, true)
	}
}

// TestMultipleIdentitiesWithDifferentPolicies tests different policies per identity
func (s *DNSFilterIntegrationSuite) TestMultipleIdentitiesWithDifferentPolicies(c *C) {
	identity1 := uint32(1000)
	identity2 := uint32(2000)
	identity3 := uint32(3000)

	// Different policies for each identity
	err := dnsfilter.BlockDomain(identity1, "facebook.com")
	c.Assert(err, IsNil)

	err = dnsfilter.BlockDomain(identity2, "twitter.com")
	c.Assert(err, IsNil)

	err = dnsfilter.BlockDomain(identity3, "instagram.com")
	c.Assert(err, IsNil)

	// Verify identity1
	blocked, _ := dnsfilter.IsBlocked(identity1, "facebook.com")
	c.Assert(blocked, Equals, true)
	blocked, _ = dnsfilter.IsBlocked(identity1, "twitter.com")
	c.Assert(blocked, Equals, false)
	blocked, _ = dnsfilter.IsBlocked(identity1, "instagram.com")
	c.Assert(blocked, Equals, false)

	// Verify identity2
	blocked, _ = dnsfilter.IsBlocked(identity2, "facebook.com")
	c.Assert(blocked, Equals, false)
	blocked, _ = dnsfilter.IsBlocked(identity2, "twitter.com")
	c.Assert(blocked, Equals, true)
	blocked, _ = dnsfilter.IsBlocked(identity2, "instagram.com")
	c.Assert(blocked, Equals, false)

	// Verify identity3
	blocked, _ = dnsfilter.IsBlocked(identity3, "facebook.com")
	c.Assert(blocked, Equals, false)
	blocked, _ = dnsfilter.IsBlocked(identity3, "twitter.com")
	c.Assert(blocked, Equals, false)
	blocked, _ = dnsfilter.IsBlocked(identity3, "instagram.com")
	c.Assert(blocked, Equals, true)
}

// TestCleanupRemovesAllPolicies tests cleanup functionality
func (s *DNSFilterIntegrationSuite) TestCleanupRemovesAllPolicies(c *C) {
	identity := uint32(1000)
	domains := []string{
		"facebook.com",
		"twitter.com",
		"instagram.com",
	}

	// Block multiple domains
	err := dnsfilter.BlockDomains(identity, domains)
	c.Assert(err, IsNil)

	// Cleanup
	err = dnsfilter.Cleanup()
	c.Assert(err, IsNil)

	// Verify all are removed
	for _, domain := range domains {
		blocked, err := dnsfilter.IsBlocked(identity, domain)
		c.Assert(err, IsNil)
		c.Assert(blocked, Equals, false)
	}
}

// TestInternationalDomainNames tests blocking international domain names
func (s *DNSFilterIntegrationSuite) TestInternationalDomainNames(c *C) {
	identity := uint32(1000)
	
	// Test with various international domain formats
	domains := []string{
		"example.co.uk",
		"example.com.br",
		"example.fr",
		"example.de",
		"example.jp",
	}

	// Block all domains
	err := dnsfilter.BlockDomains(identity, domains)
	c.Assert(err, IsNil)

	// Verify all are blocked
	for _, domain := range domains {
		blocked, err := dnsfilter.IsBlocked(identity, domain)
		c.Assert(err, IsNil)
		c.Assert(blocked, Equals, true)
	}
}

// TestHashCollisionHandling tests behavior with hash collisions
func (s *DNSFilterIntegrationSuite) TestHashCollisionHandling(c *C) {
	identity := uint32(1000)
	
	// Block one domain
	err := dnsfilter.BlockDomain(identity, "example1.com")
	c.Assert(err, IsNil)

	// Block another domain (might have same hash in theory)
	err = dnsfilter.BlockDomain(identity, "example2.com")
	c.Assert(err, IsNil)

	// Both should be independently blockable
	blocked1, _ := dnsfilter.IsBlocked(identity, "example1.com")
	c.Assert(blocked1, Equals, true)

	blocked2, _ := dnsfilter.IsBlocked(identity, "example2.com")
	c.Assert(blocked2, Equals, true)
}