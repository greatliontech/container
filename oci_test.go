package container

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func TestFromOCISpec(t *testing.T) {
	spec := &specs.Spec{
		Version: "1.0.2",
		Root:    &specs.Root{Path: "/rootfs"},
		Process: &specs.Process{
			Args: []string{"/bin/sh", "-c", "echo hello"},
			Env:  []string{"PATH=/usr/bin"},
			Cwd:  "/",
			Capabilities: &specs.LinuxCapabilities{
				Bounding:  []string{"cap_net_bind_service"},
				Effective: []string{"cap_net_bind_service"},
			},
			Rlimits: []specs.POSIXRlimit{
				{Type: "RLIMIT_NOFILE", Hard: 1024, Soft: 1024},
			},
			NoNewPrivileges: true,
		},
		Hostname: "testhost",
		Mounts: []specs.Mount{
			{
				Destination: "/proc",
				Type:        "proc",
				Source:      "proc",
				Options:     []string{"nosuid", "nodev", "noexec"},
			},
		},
		Linux: &specs.Linux{
			Namespaces: []specs.LinuxNamespace{
				{Type: specs.PIDNamespace},
				{Type: specs.MountNamespace},
				{Type: specs.UTSNamespace},
				{Type: specs.UserNamespace},
				{Type: specs.CgroupNamespace},
			},
			UIDMappings: []specs.LinuxIDMapping{
				{ContainerID: 0, HostID: 1000, Size: 1},
			},
			GIDMappings: []specs.LinuxIDMapping{
				{ContainerID: 0, HostID: 1000, Size: 1},
			},
			MaskedPaths:   []string{"/proc/kcore"},
			ReadonlyPaths: []string{"/proc/sys"},
			Sysctl:        map[string]string{"net.ipv4.ip_forward": "1"},
			Resources: &specs.LinuxResources{
				Memory: &specs.LinuxMemory{
					Limit: int64Ptr(536870912),
				},
				Pids: &specs.LinuxPids{
					Limit: int64Ptr(100),
				},
			},
		},
	}

	cfg, proc, err := FromOCISpec(spec)
	if err != nil {
		t.Fatalf("FromOCISpec: %v", err)
	}

	// Root.
	if cfg.Root != "/rootfs" {
		t.Errorf("Root = %q, want /rootfs", cfg.Root)
	}

	// Hostname.
	if cfg.Hostname != "testhost" {
		t.Errorf("Hostname = %q, want testhost", cfg.Hostname)
	}

	// Namespaces.
	if !cfg.Namespaces.NewPID {
		t.Error("NewPID should be true")
	}
	if !cfg.Namespaces.NewMnt {
		t.Error("NewMnt should be true")
	}
	if !cfg.Namespaces.NewUTS {
		t.Error("NewUTS should be true")
	}
	if !cfg.Namespaces.NewUser {
		t.Error("NewUser should be true")
	}
	if !cfg.Namespaces.NewCgroup {
		t.Error("NewCgroup should be true")
	}

	// UID mappings.
	if len(cfg.UidMappings) != 1 || cfg.UidMappings[0].HostID != 1000 {
		t.Errorf("UidMappings = %v, want [{0 1000 1}]", cfg.UidMappings)
	}

	// Mounts.
	if len(cfg.Mounts) != 1 || cfg.Mounts[0].Target != "/proc" {
		t.Errorf("Mounts = %v, want 1 mount at /proc", cfg.Mounts)
	}

	// Masked/readonly paths.
	if len(cfg.MaskPaths) != 1 || cfg.MaskPaths[0] != "/proc/kcore" {
		t.Errorf("MaskPaths = %v, want [/proc/kcore]", cfg.MaskPaths)
	}
	if len(cfg.ReadonlyPaths) != 1 || cfg.ReadonlyPaths[0] != "/proc/sys" {
		t.Errorf("ReadonlyPaths = %v, want [/proc/sys]", cfg.ReadonlyPaths)
	}

	// Sysctl.
	if cfg.Sysctl["net.ipv4.ip_forward"] != "1" {
		t.Errorf("Sysctl = %v", cfg.Sysctl)
	}

	// Resources.
	if cfg.Resources == nil || cfg.Resources.Memory == nil || cfg.Resources.Memory.Max != 536870912 {
		t.Errorf("Resources.Memory.Max = %v", cfg.Resources)
	}
	if cfg.Resources.Pids == nil || cfg.Resources.Pids.Max != 100 {
		t.Errorf("Resources.Pids.Max = %v", cfg.Resources)
	}

	// Rlimits.
	if len(cfg.Rlimits) != 1 || cfg.Rlimits[0].Soft != 1024 {
		t.Errorf("Rlimits = %v", cfg.Rlimits)
	}

	// NoNewPrivileges.
	if !cfg.NoNewPrivileges {
		t.Error("NoNewPrivileges should be true")
	}

	// Process.
	if proc.Cmd != "/bin/sh" {
		t.Errorf("Cmd = %q, want /bin/sh", proc.Cmd)
	}
	if len(proc.Args) != 2 || proc.Args[0] != "-c" {
		t.Errorf("Args = %v, want [-c 'echo hello']", proc.Args)
	}
	if proc.WorkDir != "/" {
		t.Errorf("WorkDir = %q, want /", proc.WorkDir)
	}

	// Capabilities.
	if cfg.Capabilities == nil || len(cfg.Capabilities.Bounding) == 0 {
		t.Error("Capabilities should be set")
	}
}

func TestFromOCISpec_RootReadonly(t *testing.T) {
	spec := &specs.Spec{
		Root: &specs.Root{Path: "/rootfs", Readonly: true},
	}
	cfg, _, err := FromOCISpec(spec)
	if err != nil {
		t.Fatalf("FromOCISpec: %v", err)
	}
	if !cfg.ReadonlyRoot {
		t.Error("ReadonlyRoot should be true")
	}
}

func TestFromOCISpec_Domainname(t *testing.T) {
	spec := &specs.Spec{
		Root:       &specs.Root{Path: "/rootfs"},
		Domainname: "example.com",
	}
	cfg, _, err := FromOCISpec(spec)
	if err != nil {
		t.Fatalf("FromOCISpec: %v", err)
	}
	if cfg.Domainname != "example.com" {
		t.Errorf("Domainname = %q, want example.com", cfg.Domainname)
	}
}

func TestFromOCISpec_Annotations(t *testing.T) {
	spec := &specs.Spec{
		Root:        &specs.Root{Path: "/rootfs"},
		Annotations: map[string]string{"org.test.key": "value"},
	}
	cfg, _, err := FromOCISpec(spec)
	if err != nil {
		t.Fatalf("FromOCISpec: %v", err)
	}
	if cfg.Annotations["org.test.key"] != "value" {
		t.Errorf("Annotations = %v", cfg.Annotations)
	}
}

func TestFromOCISpec_NamespaceJoin(t *testing.T) {
	spec := &specs.Spec{
		Root: &specs.Root{Path: "/rootfs"},
		Linux: &specs.Linux{
			Namespaces: []specs.LinuxNamespace{
				{Type: specs.NetworkNamespace, Path: "/var/run/netns/mynet"},
				{Type: specs.PIDNamespace},
			},
		},
	}

	cfg, _, err := FromOCISpec(spec)
	if err != nil {
		t.Fatalf("FromOCISpec: %v", err)
	}

	if cfg.Namespaces.JoinNet != "/var/run/netns/mynet" {
		t.Errorf("JoinNet = %q, want /var/run/netns/mynet", cfg.Namespaces.JoinNet)
	}
	if !cfg.Namespaces.NewPID {
		t.Error("NewPID should be true")
	}
	if cfg.Namespaces.NewNet {
		t.Error("NewNet should be false when joining")
	}
}

func TestLoadOCIBundle(t *testing.T) {
	bundleDir := t.TempDir()
	rootfsDir := filepath.Join(bundleDir, "rootfs")
	if err := os.MkdirAll(rootfsDir, 0755); err != nil {
		t.Fatal(err)
	}

	spec := specs.Spec{
		Version:  "1.0.2",
		Root:     &specs.Root{Path: "rootfs"},
		Hostname: "bundletest",
		Process: &specs.Process{
			Args: []string{"/bin/sh"},
			Cwd:  "/",
		},
		Linux: &specs.Linux{
			Namespaces: []specs.LinuxNamespace{
				{Type: specs.PIDNamespace},
				{Type: specs.MountNamespace},
			},
		},
	}

	data, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundleDir, "config.json"), data, 0644); err != nil {
		t.Fatal(err)
	}

	cfg, proc, err := LoadOCIBundle(bundleDir)
	if err != nil {
		t.Fatalf("LoadOCIBundle: %v", err)
	}

	// Root should be absolute (resolved relative to bundle).
	if !filepath.IsAbs(cfg.Root) {
		t.Errorf("Root = %q, should be absolute", cfg.Root)
	}
	expectedRoot := filepath.Join(bundleDir, "rootfs")
	if cfg.Root != expectedRoot {
		t.Errorf("Root = %q, want %q", cfg.Root, expectedRoot)
	}

	if cfg.Hostname != "bundletest" {
		t.Errorf("Hostname = %q, want bundletest", cfg.Hostname)
	}

	if proc.Cmd != "/bin/sh" {
		t.Errorf("Cmd = %q, want /bin/sh", proc.Cmd)
	}
}

func int64Ptr(v int64) *int64 { return &v }
