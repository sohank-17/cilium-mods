# Cilium Advanced Security Features

This document describes two new security features added to Cilium for enhanced egress traffic control and data exfiltration prevention.

---

## Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Installation](#installation)
4. [Usage](#usage)
5. [Architecture](#architecture)
6. [Testing](#testing)

---

## Overview

We've implemented two security features for Cilium:

1. **Payload Size-Based Filtering** - Block outgoing packets exceeding configured size limits
2. **DNS Domain-Based Blocking** - Block DNS queries to specific domains

Both features operate at the eBPF datapath level for high performance and low overhead.

---

## Features

### 1. Payload Size-Based Filtering

Inspects egress packets from containers and drops those exceeding a configured payload size threshold.

**Key Capabilities:**
- Per-identity or per-namespace payload size limits
- Protocol-aware (handles TCP, UDP differently)
- Real-time alerting to log files
- Zero performance impact on allowed traffic

**Use Cases:**
- Prevent data exfiltration via large file uploads
- Enforce organizational data transfer policies
- Detect anomalous traffic patterns
- Limit bandwidth abuse

**Example:** Drop HTTP POST requests with payloads larger than 1MB from a specific pod.

### 2. DNS Domain-Based Blocking

Inspects DNS queries (UDP port 53) and blocks requests to disallowed domains.

**Key Capabilities:**
- Per-identity domain blocking
- Wildcard domain support (e.g., `*.facebook.com`)
- Case-insensitive domain matching
- Real-time alerting to log files
- No impact on DNS responses

**Use Cases:**
- Prevent exfiltration via DNS tunneling
- Enforce acceptable use policies
- Block access to malicious domains
- Restrict communication to known services

**Example:** Block all DNS queries to `facebook.com` and `dropbox.com` from selected pods.

---

## Installation

### Prerequisites

- Cilium installed and running
- Kernel version 4.15 or higher
- Root/privileged access

### Enable Features

Add to Cilium configuration file or use command-line flags:
```yaml
# /etc/cilium/cilium-config.yaml
enable-payload-filter: true
enable-dns-filter: true
```

Or via command line:
```bash
cilium-agent --enable-payload-filter=true --enable-dns-filter=true
```

### Verify Installation
```bash
# Check feature flags
cilium config view | grep -E "payload-filter|dns-filter"

# Check eBPF programs loaded
bpftool prog list | grep -E "payload|dns"

# Check maps created
bpftool map list | grep -E "payload|dns"
```

---

## Usage

### Payload Size-Based Filtering

#### Add Payload Size Limit
```bash
# Syntax
cilium-agent add payload-filter <pod_id> <max-size-bytes>

# Examples
cilium-agent add payload-filter <pod_id> 1048576     # 1MB limit
```

#### Remove Payload Size Limit
```bash
cilium-agent remove payload-filter <pod_id>

# Example
cilium-agent remove payload-filter <pod_id>
```

#### List Payload Filters
```bash
cilium-agent list payload-filter

# Example output:
# Identity    Max Size      Status
# <pod_id1>       1048576       Active
# <pod_id2>       5242880       Active
# <pod_id3>       524288        Active
```

#### View Alerts
```bash
# Real-time monitoring
tail -f /var/log/cilium/payload-filter-alerts.log

# Example log entry:
# 2024-01-15T10:30:45Z identity=12345 payload_size=2097152 limit=1048576 protocol=TCP action=DROP
```

---

### DNS Domain-Based Blocking

#### Add DNS Domain Block
```bash
# Syntax
cilium-agent add dns-filter <pod_id> <domain>

# Examples
cilium-agent add dns-filter <pod_id> facebook.com
```

#### Remove DNS Domain Block
```bash
cilium-agent remove dns-filter <pod_id> <domain>

# Example
cilium-agent remove dns-filter <pod_id> facebook.com
```

#### List DNS Filters
```bash
cilium-agent list dns-filter

# Example output:
# Identity    Domain              Status
# <pod_id1>       facebook.com        Blocked
# <pod_id1>       twitter.com         Blocked
```

#### View DNS Block Alerts
```bash
# Real-time monitoring
tail -f /var/log/cilium/dns-filter-alerts.log

# Example log entry:
# 2024-01-15T10:31:22Z identity=12345 domain=facebook.com src_ip=10.0.1.5 dst_ip=8.8.8.8 action=BLOCK
```

---

## Architecture

### File Structure
```
cilium/
├── bpf/
│   ├── lib/
│   │   ├── payload_filter.h         # eBPF payload filtering logic
│   │   ├── dns_filter.h             # eBPF DNS filtering logic
│   │   └── drop.h                   # Drop reason codes (modified)
│   ├── bpf_lxc.c                    # Main datapath (modified)
│   └── tests/
│       ├── payload_filter_test.c    # eBPF tests for payload filter
│       └── dns_filter_test.c        # eBPF tests for DNS filter
├── pkg/
│   ├── maps/
│   │   ├── payloadfilter/
│   │   │   ├── payload_filter.go    # Go map wrapper for payload filter
│   │   │   └── payload_filter_test.go
│   │   └── dnsfilter/
│   │       ├── dns_filter.go        # Go map wrapper for DNS filter
│   │       └── dns_filter_test.go
│   ├── option/
│   │   └── config.go                # Feature flags (modified)
│   └── datapath/
│       └── loader/
│           └── loader.go            # Map initialization (modified)
├── daemon/
│   └── cmd/
│       └── daemon.go                # Event listeners (modified)
└── test/
    └── integration/
        ├── payload_filter_test.go   # Integration tests
        └── dns_filter_test.go       # Integration tests
```

### Component Overview

#### eBPF Datapath (Kernel Space)
- **Entry Point:** `cil_from_container()` in `bpf/bpf_lxc.c`
- **Payload Filter:** `payload_filter_check()` calculates packet payload size and compares against limits
- **DNS Filter:** `dns_filter_check()` parses DNS queries and checks domains against block list
- **Maps:** Hash maps store policies (identity → limit or identity+domain_hash → action)
- **Events:** Perf buffers send violation alerts to userspace

#### Control Plane (User Space)
- **Map Management:** Go wrappers provide API for policy CRUD operations
- **Event Processing:** Daemon goroutines read perf buffers and write to log files
- **Configuration:** Feature flags control compilation and runtime behavior

### Data Flow
```
Container Egress Packet
         ↓
   TC Egress Hook
         ↓
  cil_from_container()
         ↓
  ┌──────────────┐
  │ Payload      │ → Check size → Drop if > limit
  │ Filter       │                ↓
  └──────────────┘         Log to file
         ↓
  ┌──────────────┐
  │ DNS          │ → Parse query → Block if in list
  │ Filter       │                 ↓
  └──────────────┘          Log to file
         ↓
  Protocol Processing
         ↓
     Forward Packet
```

---

## Testing

### Unit Tests
```bash
# Payload filter Go tests
cd pkg/maps/payloadfilter && go test -v

# DNS filter Go tests
cd pkg/maps/dnsfilter && go test -v

# eBPF tests
cd bpf/tests && make test
```

### Integration Tests
Located in test/k8s/dns_filter_test.go and test/k8s/payload_filter.go files.

### Manual Testing

#### Test Payload Filter
```bash
# 1. Set a small limit
cilium-agent add payload-filter <pod_id> 1024    # 1KB limit

# 2. Try to send large packet from pod with identity 12345
# This should be blocked and logged

# 3. Check logs
tail -f /var/log/cilium/payload-filter-alerts.log
```

#### Test DNS Filter
```bash
# 1. Block a domain
cilium-agent add dns-filter facebook.com

# 2. Try to resolve from pod with identity 12345
nslookup facebook.com    # Should fail/timeout

# 3. Check logs
tail -f /var/log/cilium/dns-filter-alerts.log

```

### Log File Locations
```
Payload Filter Alerts: /var/log/cilium/payload-filter-alerts.log
DNS Filter Alerts:     /var/log/cilium/dns-filter-alerts.log
Cilium Main Log:       /var/log/cilium/cilium.log
```

---
