package container

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
)

// Unit tests for network (no root required)

func TestAllocateIP(t *testing.T) {
	tests := []struct {
		name    string
		subnet  string
		used    []string
		wantIP  string
		wantErr bool
	}{
		{
			name:   "first IP from /24",
			subnet: "10.88.0.0/24",
			used:   nil,
			wantIP: "10.88.0.2/24", // .0 is network, .1 is gateway
		},
		{
			name:   "first IP from /16",
			subnet: "10.88.0.0/16",
			used:   nil,
			wantIP: "10.88.0.2/16",
		},
		{
			name:   "skip used IPs",
			subnet: "10.88.0.0/24",
			used:   []string{"10.88.0.2", "10.88.0.3", "10.88.0.4"},
			wantIP: "10.88.0.5/24",
		},
		{
			name:   "skip non-sequential used IPs",
			subnet: "10.88.0.0/24",
			used:   []string{"10.88.0.2", "10.88.0.5"},
			wantIP: "10.88.0.3/24", // Returns first available
		},
		{
			name:   "different subnet",
			subnet: "192.168.1.0/24",
			used:   nil,
			wantIP: "192.168.1.2/24",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := AllocateIP(tt.subnet, tt.used)
			if (err != nil) != tt.wantErr {
				t.Errorf("AllocateIP() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.wantIP {
				t.Errorf("AllocateIP() = %v, want %v", got, tt.wantIP)
			}
		})
	}
}

func TestAllocateIP_Used(t *testing.T) {
	// Build a list of all IPs from .2 to .254
	used := make([]string, 0, 253)
	for i := 2; i < 100; i++ {
		used = append(used, "10.88.0."+string(rune('0'+i/100))+string(rune('0'+(i%100)/10))+string(rune('0'+i%10)))
	}

	// Manually build correct strings
	used = []string{
		"10.88.0.2", "10.88.0.3", "10.88.0.4", "10.88.0.5",
		"10.88.0.6", "10.88.0.7", "10.88.0.8", "10.88.0.9",
	}

	ip, err := AllocateIP("10.88.0.0/24", used)
	if err != nil {
		t.Fatalf("AllocateIP failed: %v", err)
	}

	// Should return .10 since .2-.9 are used
	if ip != "10.88.0.10/24" {
		t.Errorf("AllocateIP() = %v, want 10.88.0.10/24", ip)
	}
}

func TestAllocateIP_Exhausted(t *testing.T) {
	// Build a list of all IPs from .2 to .254
	used := make([]string, 253)
	for i := 2; i <= 254; i++ {
		used[i-2] = "10.88.0." + strings.TrimLeft("000"+string(rune('0'+i/100)+rune('0'+(i%100)/10)+rune('0'+i%10)), "0")
	}

	// Manually build for simplicity
	used = make([]string, 253)
	for i := 2; i <= 254; i++ {
		s := ""
		if i >= 100 {
			s = string(rune('0'+i/100)) + string(rune('0'+(i%100)/10)) + string(rune('0'+i%10))
		} else if i >= 10 {
			s = string(rune('0'+i/10)) + string(rune('0'+i%10))
		} else {
			s = string(rune('0' + i))
		}
		used[i-2] = "10.88.0." + s
	}

	_, err := AllocateIP("10.88.0.0/24", used)
	if err == nil {
		t.Error("AllocateIP() should return error when subnet exhausted")
	}
}

func TestAllocateIP_InvalidSubnet(t *testing.T) {
	_, err := AllocateIP("invalid", nil)
	if err == nil {
		t.Error("AllocateIP() should return error for invalid subnet")
	}
}

func TestWriteResolvConf(t *testing.T) {
	tmpDir := t.TempDir()

	// Test with custom DNS servers
	dns := []string{"1.1.1.1", "8.8.8.8"}
	if err := WriteResolvConf(tmpDir, dns); err != nil {
		t.Fatalf("WriteResolvConf failed: %v", err)
	}

	// Verify file was created
	resolvPath := filepath.Join(tmpDir, "etc", "resolv.conf")
	data, err := os.ReadFile(resolvPath)
	if err != nil {
		t.Fatalf("failed to read resolv.conf: %v", err)
	}

	content := string(data)

	// Verify DNS servers are present
	for _, server := range dns {
		if !strings.Contains(content, "nameserver "+server) {
			t.Errorf("resolv.conf missing nameserver %s", server)
		}
	}
}

func TestWriteResolvConf_DefaultDNS(t *testing.T) {
	tmpDir := t.TempDir()

	// Test with no DNS servers (should use defaults)
	if err := WriteResolvConf(tmpDir, nil); err != nil {
		t.Fatalf("WriteResolvConf failed: %v", err)
	}

	resolvPath := filepath.Join(tmpDir, "etc", "resolv.conf")
	data, err := os.ReadFile(resolvPath)
	if err != nil {
		t.Fatalf("failed to read resolv.conf: %v", err)
	}

	content := string(data)

	// Should contain default DNS (8.8.8.8 and 8.8.4.4)
	if !strings.Contains(content, "nameserver 8.8.8.8") {
		t.Error("resolv.conf missing default nameserver 8.8.8.8")
	}
	if !strings.Contains(content, "nameserver 8.8.4.4") {
		t.Error("resolv.conf missing default nameserver 8.8.4.4")
	}
}

func TestWriteHosts(t *testing.T) {
	tmpDir := t.TempDir()

	hostname := "testcontainer"
	ipAddress := "10.88.0.5/24"

	if err := WriteHosts(tmpDir, hostname, ipAddress); err != nil {
		t.Fatalf("WriteHosts failed: %v", err)
	}

	hostsPath := filepath.Join(tmpDir, "etc", "hosts")
	data, err := os.ReadFile(hostsPath)
	if err != nil {
		t.Fatalf("failed to read hosts: %v", err)
	}

	content := string(data)

	// Verify localhost entries
	if !strings.Contains(content, "127.0.0.1\tlocalhost") {
		t.Error("hosts file missing 127.0.0.1 localhost entry")
	}
	if !strings.Contains(content, "::1") {
		t.Error("hosts file missing IPv6 localhost entry")
	}

	// Verify hostname entry (IP without CIDR suffix)
	if !strings.Contains(content, "10.88.0.5\ttestcontainer") {
		t.Error("hosts file missing hostname entry")
	}

	// Should NOT contain CIDR suffix
	if strings.Contains(content, "/24") {
		t.Error("hosts file should not contain CIDR suffix")
	}
}

func TestWriteHosts_NoIPAddress(t *testing.T) {
	tmpDir := t.TempDir()

	// Test with no IP address
	if err := WriteHosts(tmpDir, "testhost", ""); err != nil {
		t.Fatalf("WriteHosts failed: %v", err)
	}

	hostsPath := filepath.Join(tmpDir, "etc", "hosts")
	data, err := os.ReadFile(hostsPath)
	if err != nil {
		t.Fatalf("failed to read hosts: %v", err)
	}

	content := string(data)

	// Should still have localhost
	if !strings.Contains(content, "127.0.0.1\tlocalhost") {
		t.Error("hosts file missing localhost entry")
	}
}

func TestNetworkModeConstants(t *testing.T) {
	// Verify network mode constants
	if NetworkModeNone != "none" {
		t.Errorf("NetworkModeNone = %s, want none", NetworkModeNone)
	}
	if NetworkModeHost != "host" {
		t.Errorf("NetworkModeHost = %s, want host", NetworkModeHost)
	}
	if NetworkModeBridge != "bridge" {
		t.Errorf("NetworkModeBridge = %s, want bridge", NetworkModeBridge)
	}
}

func TestNetworkConfigStruct(t *testing.T) {
	cfg := NetworkConfig{
		Mode:      NetworkModeBridge,
		Bridge:    "container0",
		IPAddress: "10.88.0.5/16",
		Gateway:   "10.88.0.1",
		DNS:       []string{"8.8.8.8"},
		Hostname:  "test",
		PortMappings: []PortMapping{
			{HostPort: 8080, ContainerPort: 80, Protocol: "tcp"},
		},
	}

	if cfg.Mode != NetworkModeBridge {
		t.Errorf("Mode = %s, want bridge", cfg.Mode)
	}
	if cfg.Bridge != "container0" {
		t.Errorf("Bridge = %s, want container0", cfg.Bridge)
	}
	if cfg.IPAddress != "10.88.0.5/16" {
		t.Errorf("IPAddress = %s, want 10.88.0.5/16", cfg.IPAddress)
	}
	if cfg.Gateway != "10.88.0.1" {
		t.Errorf("Gateway = %s, want 10.88.0.1", cfg.Gateway)
	}
	if len(cfg.DNS) != 1 || cfg.DNS[0] != "8.8.8.8" {
		t.Errorf("DNS = %v, want [8.8.8.8]", cfg.DNS)
	}
	if len(cfg.PortMappings) != 1 {
		t.Errorf("PortMappings length = %d, want 1", len(cfg.PortMappings))
	}
}

func TestDefaultBridgeConstants(t *testing.T) {
	if DefaultBridgeName != "container0" {
		t.Errorf("DefaultBridgeName = %s, want container0", DefaultBridgeName)
	}
	if DefaultBridgeSubnet != "10.88.0.0/16" {
		t.Errorf("DefaultBridgeSubnet = %s, want 10.88.0.0/16", DefaultBridgeSubnet)
	}
	if DefaultBridgeGateway != "10.88.0.1/16" {
		t.Errorf("DefaultBridgeGateway = %s, want 10.88.0.1/16", DefaultBridgeGateway)
	}
}

// Integration tests for network (require root)
// These tests require the "integration" build tag to run:
// go test -tags=integration ./...

func TestEnsureBridge_Create(t *testing.T) {
	skipIfNotRoot(t)
	skipIfNoNetwork(t)

	bridgeName := "test-br-" + generateTestID(t)[:8]
	defer func() {
		// Cleanup
		if link, err := netlink.LinkByName(bridgeName); err == nil {
			netlink.LinkDel(link)
		}
	}()

	br, err := EnsureBridge(bridgeName)
	if err != nil {
		t.Fatalf("EnsureBridge failed: %v", err)
	}

	if br == nil {
		t.Fatal("EnsureBridge returned nil")
	}

	// Verify bridge was created
	link, err := netlink.LinkByName(bridgeName)
	if err != nil {
		t.Fatalf("bridge not found: %v", err)
	}

	// Verify it's a bridge type
	if _, ok := link.(*netlink.Bridge); !ok {
		t.Errorf("link is not a bridge: %T", link)
	}

	// Verify bridge is up
	if link.Attrs().Flags&1 == 0 {
		t.Error("bridge should be up")
	}
}

func TestEnsureBridge_Idempotent(t *testing.T) {
	skipIfNotRoot(t)
	skipIfNoNetwork(t)

	bridgeName := "test-br-" + generateTestID(t)[:8]
	defer func() {
		if link, err := netlink.LinkByName(bridgeName); err == nil {
			netlink.LinkDel(link)
		}
	}()

	// Create bridge first time
	br1, err := EnsureBridge(bridgeName)
	if err != nil {
		t.Fatalf("first EnsureBridge failed: %v", err)
	}

	// Create bridge second time (should return existing)
	br2, err := EnsureBridge(bridgeName)
	if err != nil {
		t.Fatalf("second EnsureBridge failed: %v", err)
	}

	// Both should refer to the same bridge
	if br1.Attrs().Index != br2.Attrs().Index {
		t.Error("EnsureBridge should return existing bridge")
	}
}

func TestSetupContainerNetwork_None(t *testing.T) {
	skipIfNotRoot(t)

	cfg := NetworkConfig{Mode: NetworkModeNone}

	// Should succeed without actually setting up network
	net, err := SetupContainerNetwork(1, cfg)
	if err != nil {
		t.Fatalf("SetupContainerNetwork failed: %v", err)
	}

	if net == nil {
		t.Fatal("SetupContainerNetwork returned nil")
	}

	// Cleanup should be no-op
	if err := net.Cleanup(); err != nil {
		t.Errorf("Cleanup failed: %v", err)
	}
}

func TestSetupContainerNetwork_Host(t *testing.T) {
	skipIfNotRoot(t)

	cfg := NetworkConfig{Mode: NetworkModeHost}

	// Should succeed without actually setting up network
	net, err := SetupContainerNetwork(1, cfg)
	if err != nil {
		t.Fatalf("SetupContainerNetwork failed: %v", err)
	}

	if net == nil {
		t.Fatal("SetupContainerNetwork returned nil")
	}
}

func TestNetwork_Cleanup(t *testing.T) {
	skipIfNotRoot(t)

	// Test cleanup with nil/empty network
	net := &Network{}
	if err := net.Cleanup(); err != nil {
		t.Errorf("Cleanup on empty network failed: %v", err)
	}
}
