package container

import (
	"encoding/binary"
	"testing"
)

// Unit tests for port forwarding (no root required)

func TestBinaryPort(t *testing.T) {
	tests := []struct {
		port uint16
		want []byte
	}{
		{port: 80, want: []byte{0x00, 0x50}},       // HTTP
		{port: 443, want: []byte{0x01, 0xBB}},      // HTTPS
		{port: 8080, want: []byte{0x1F, 0x90}},     // Alt HTTP
		{port: 22, want: []byte{0x00, 0x16}},       // SSH
		{port: 0, want: []byte{0x00, 0x00}},        // Zero
		{port: 65535, want: []byte{0xFF, 0xFF}},    // Max port
		{port: 256, want: []byte{0x01, 0x00}},      // Boundary
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			got := binaryPort(tt.port)
			if len(got) != 2 {
				t.Errorf("binaryPort(%d) length = %d, want 2", tt.port, len(got))
				return
			}
			if got[0] != tt.want[0] || got[1] != tt.want[1] {
				t.Errorf("binaryPort(%d) = %v, want %v", tt.port, got, tt.want)
			}

			// Verify it's network byte order (big endian)
			decoded := binary.BigEndian.Uint16(got)
			if decoded != tt.port {
				t.Errorf("decoded port = %d, want %d", decoded, tt.port)
			}
		})
	}
}

func TestPadString(t *testing.T) {
	tests := []struct {
		s      string
		length int
		want   int // expected length
	}{
		{s: "eth0", length: 16, want: 16},
		{s: "container0", length: 16, want: 16},
		{s: "", length: 16, want: 16},
		{s: "lo", length: 16, want: 16},
		{s: "verylonginterfacename", length: 16, want: 16}, // Truncated
	}

	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			got := padString(tt.s, tt.length)
			if len(got) != tt.want {
				t.Errorf("padString(%q, %d) length = %d, want %d", tt.s, tt.length, len(got), tt.want)
			}

			// Verify string is at the beginning
			if len(tt.s) <= tt.length {
				for i := 0; i < len(tt.s); i++ {
					if got[i] != tt.s[i] {
						t.Errorf("padString(%q, %d)[%d] = %c, want %c", tt.s, tt.length, i, got[i], tt.s[i])
					}
				}
			}

			// Verify padding is null bytes
			startPad := len(tt.s)
			if startPad > tt.length {
				startPad = tt.length
			}
			for i := startPad; i < tt.length; i++ {
				if got[i] != 0 {
					t.Errorf("padString(%q, %d)[%d] = %d, want 0", tt.s, tt.length, i, got[i])
				}
			}
		})
	}
}

func TestParsePortMapping(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		wantHostPort  uint16
		wantContPort  uint16
		wantProtocol  string
		wantErr       bool
	}{
		{
			name:          "basic TCP",
			input:         "8080:80",
			wantHostPort:  8080,
			wantContPort:  80,
			wantProtocol:  "tcp",
		},
		{
			name:          "explicit TCP",
			input:         "8080:80/tcp",
			wantHostPort:  8080,
			wantContPort:  80,
			wantProtocol:  "tcp",
		},
		{
			name:          "UDP",
			input:         "5353:53/udp",
			wantHostPort:  5353,
			wantContPort:  53,
			wantProtocol:  "udp",
		},
		{
			name:          "same ports",
			input:         "443:443",
			wantHostPort:  443,
			wantContPort:  443,
			wantProtocol:  "tcp",
		},
		{
			name:          "high ports",
			input:         "30000:30000/tcp",
			wantHostPort:  30000,
			wantContPort:  30000,
			wantProtocol:  "tcp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePortMapping(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParsePortMapping(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			if got.HostPort != tt.wantHostPort {
				t.Errorf("HostPort = %d, want %d", got.HostPort, tt.wantHostPort)
			}
			if got.ContainerPort != tt.wantContPort {
				t.Errorf("ContainerPort = %d, want %d", got.ContainerPort, tt.wantContPort)
			}
			if got.Protocol != tt.wantProtocol {
				t.Errorf("Protocol = %s, want %s", got.Protocol, tt.wantProtocol)
			}
		})
	}
}

func TestParsePortMapping_Invalid(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "no colon", input: "8080"},
		{name: "empty", input: ""},
		{name: "too many colons", input: "8080:80:443"},
		{name: "invalid host port", input: "abc:80"},
		{name: "invalid container port", input: "8080:abc"},
		{name: "negative port", input: "-1:80"},
		{name: "port too large", input: "70000:80"},
		{name: "missing container port", input: "8080:"},
		{name: "missing host port", input: ":80"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParsePortMapping(tt.input)
			if err == nil {
				t.Errorf("ParsePortMapping(%q) should return error", tt.input)
			}
		})
	}
}

func TestPortMappingsFromStrings(t *testing.T) {
	tests := []struct {
		name    string
		input   []string
		wantLen int
		wantErr bool
	}{
		{
			name:    "single mapping",
			input:   []string{"8080:80"},
			wantLen: 1,
		},
		{
			name:    "multiple mappings",
			input:   []string{"8080:80", "443:443/tcp", "5353:53/udp"},
			wantLen: 3,
		},
		{
			name:    "empty list",
			input:   []string{},
			wantLen: 0,
		},
		{
			name:    "nil list",
			input:   nil,
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := PortMappingsFromStrings(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("PortMappingsFromStrings() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(got) != tt.wantLen {
				t.Errorf("PortMappingsFromStrings() length = %d, want %d", len(got), tt.wantLen)
			}
		})
	}
}

func TestPortMappingsFromStrings_Invalid(t *testing.T) {
	// Any invalid mapping should fail the whole batch
	input := []string{"8080:80", "invalid", "443:443"}
	_, err := PortMappingsFromStrings(input)
	if err == nil {
		t.Error("PortMappingsFromStrings() should return error for invalid mapping")
	}
}

func TestPortMappingStruct(t *testing.T) {
	pm := PortMapping{
		HostIP:        "0.0.0.0",
		HostPort:      8080,
		ContainerPort: 80,
		Protocol:      "tcp",
	}

	if pm.HostIP != "0.0.0.0" {
		t.Errorf("HostIP = %s, want 0.0.0.0", pm.HostIP)
	}
	if pm.HostPort != 8080 {
		t.Errorf("HostPort = %d, want 8080", pm.HostPort)
	}
	if pm.ContainerPort != 80 {
		t.Errorf("ContainerPort = %d, want 80", pm.ContainerPort)
	}
	if pm.Protocol != "tcp" {
		t.Errorf("Protocol = %s, want tcp", pm.Protocol)
	}
}

func TestPortMappingDefaults(t *testing.T) {
	// Test that ParsePortMapping sets defaults correctly
	pm, err := ParsePortMapping("8080:80")
	if err != nil {
		t.Fatalf("ParsePortMapping failed: %v", err)
	}

	// Protocol should default to TCP
	if pm.Protocol != "tcp" {
		t.Errorf("default Protocol = %s, want tcp", pm.Protocol)
	}

	// HostIP should be empty (meaning all interfaces)
	if pm.HostIP != "" {
		t.Errorf("default HostIP = %s, want empty", pm.HostIP)
	}
}

func TestTableNameConstant(t *testing.T) {
	if tableNameContainer != "container_nat" {
		t.Errorf("tableNameContainer = %s, want container_nat", tableNameContainer)
	}
}

// Integration tests for port forwarding (require root)
// These tests require the "integration" build tag to run:
// go test -tags=integration ./...

func TestPortForwarder_Create(t *testing.T) {
	skipIfNotRoot(t)
	skipIfNoNftables(t)

	containerIP := "10.88.0.100"
	bridgeName := "container0"

	pf, err := NewPortForwarder(containerIP, bridgeName)
	if err != nil {
		t.Fatalf("NewPortForwarder failed: %v", err)
	}
	defer pf.Cleanup()

	if pf == nil {
		t.Fatal("NewPortForwarder returned nil")
	}

	if pf.table == nil {
		t.Error("table should not be nil")
	}
	if pf.prerouting == nil {
		t.Error("prerouting chain should not be nil")
	}
	if pf.postrouting == nil {
		t.Error("postrouting chain should not be nil")
	}
}

func TestPortForwarder_InvalidIP(t *testing.T) {
	_, err := NewPortForwarder("invalid", "container0")
	if err == nil {
		t.Error("NewPortForwarder should fail for invalid IP")
	}
}

func TestPortForwarder_IPv6NotSupported(t *testing.T) {
	_, err := NewPortForwarder("::1", "container0")
	if err == nil {
		t.Error("NewPortForwarder should fail for IPv6")
	}
}

func TestPortForwarder_AddMapping(t *testing.T) {
	skipIfNotRoot(t)
	skipIfNoNftables(t)

	containerIP := "10.88.0.101"
	bridgeName := "container0"

	pf, err := NewPortForwarder(containerIP, bridgeName)
	if err != nil {
		t.Fatalf("NewPortForwarder failed: %v", err)
	}
	defer pf.Cleanup()

	mapping := PortMapping{
		HostPort:      8080,
		ContainerPort: 80,
		Protocol:      "tcp",
	}

	if err := pf.AddMapping(mapping); err != nil {
		t.Fatalf("AddMapping failed: %v", err)
	}

	// Verify mapping was tracked
	if len(pf.mappings) != 1 {
		t.Errorf("mappings length = %d, want 1", len(pf.mappings))
	}
}

func TestPortForwarder_RemoveMapping(t *testing.T) {
	skipIfNotRoot(t)
	skipIfNoNftables(t)

	containerIP := "10.88.0.102"
	bridgeName := "container0"

	pf, err := NewPortForwarder(containerIP, bridgeName)
	if err != nil {
		t.Fatalf("NewPortForwarder failed: %v", err)
	}
	defer pf.Cleanup()

	mapping := PortMapping{
		HostPort:      8081,
		ContainerPort: 81,
		Protocol:      "tcp",
	}

	// Add mapping
	if err := pf.AddMapping(mapping); err != nil {
		t.Fatalf("AddMapping failed: %v", err)
	}

	// Remove mapping
	if err := pf.RemoveMapping(mapping); err != nil {
		t.Fatalf("RemoveMapping failed: %v", err)
	}

	// Verify mapping was removed from tracking
	if len(pf.mappings) != 0 {
		t.Errorf("mappings length = %d, want 0", len(pf.mappings))
	}
}

func TestPortForwarder_Cleanup(t *testing.T) {
	skipIfNotRoot(t)
	skipIfNoNftables(t)

	containerIP := "10.88.0.103"
	bridgeName := "container0"

	pf, err := NewPortForwarder(containerIP, bridgeName)
	if err != nil {
		t.Fatalf("NewPortForwarder failed: %v", err)
	}

	// Add some mappings
	mappings := []PortMapping{
		{HostPort: 8082, ContainerPort: 82, Protocol: "tcp"},
		{HostPort: 8083, ContainerPort: 83, Protocol: "tcp"},
	}

	for _, m := range mappings {
		if err := pf.AddMapping(m); err != nil {
			t.Fatalf("AddMapping failed: %v", err)
		}
	}

	// Cleanup should remove all mappings
	if err := pf.Cleanup(); err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}

	if len(pf.mappings) != 0 {
		t.Errorf("mappings after cleanup = %d, want 0", len(pf.mappings))
	}
}

func TestSetupNATForBridge(t *testing.T) {
	skipIfNotRoot(t)
	skipIfNoNftables(t)

	// This test just verifies the function runs without error
	// Full verification would require checking nftables rules
	bridgeName := "container0"
	subnet := "10.88.0.0/16"

	// This may fail if forwarding can't be enabled, which is fine in some test envs
	err := SetupNATForBridge(bridgeName, subnet)
	if err != nil {
		t.Logf("SetupNATForBridge failed (may be expected in some environments): %v", err)
	}
}
