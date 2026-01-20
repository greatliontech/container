package container

import (
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// NetworkMode defines the container networking mode
type NetworkMode string

const (
	// NetworkModeNone - container has no network connectivity
	NetworkModeNone NetworkMode = "none"
	// NetworkModeHost - container shares host network namespace
	NetworkModeHost NetworkMode = "host"
	// NetworkModeBridge - container connects to a bridge network
	NetworkModeBridge NetworkMode = "bridge"
)

// NetworkConfig defines the network configuration for a container
type NetworkConfig struct {
	// Mode is the networking mode
	Mode NetworkMode

	// Bridge is the bridge name to connect to (for bridge mode)
	// If empty, defaults to "container0"
	Bridge string

	// IPAddress is the container's IP address with CIDR (e.g., "10.0.0.2/24")
	// If empty in bridge mode, will need manual configuration
	IPAddress string

	// Gateway is the default gateway IP
	Gateway string

	// DNS is a list of DNS server IPs
	DNS []string

	// Hostname is the container hostname (also set via Config.Hostname)
	Hostname string
}

// Network manages container networking
type Network struct {
	config     NetworkConfig
	bridge     netlink.Link
	vethHost   netlink.Link
	vethPeer   string
	containerNS netns.NsHandle
}

// DefaultBridgeName is the default bridge name for container networking
const DefaultBridgeName = "container0"

// DefaultBridgeSubnet is the default subnet for the container bridge
const DefaultBridgeSubnet = "10.88.0.0/16"

// DefaultBridgeGateway is the default gateway for the container bridge
const DefaultBridgeGateway = "10.88.0.1/16"

// EnsureBridge creates the container bridge if it doesn't exist
func EnsureBridge(name string) (netlink.Link, error) {
	if name == "" {
		name = DefaultBridgeName
	}

	// Check if bridge already exists
	br, err := netlink.LinkByName(name)
	if err == nil {
		return br, nil
	}

	// Create new bridge
	la := netlink.NewLinkAttrs()
	la.Name = name
	bridge := &netlink.Bridge{LinkAttrs: la}

	if err := netlink.LinkAdd(bridge); err != nil {
		return nil, fmt.Errorf("create bridge: %w", err)
	}

	// Get the bridge link
	br, err = netlink.LinkByName(name)
	if err != nil {
		return nil, fmt.Errorf("get bridge: %w", err)
	}

	// Assign IP address to bridge
	addr, err := netlink.ParseAddr(DefaultBridgeGateway)
	if err != nil {
		return nil, fmt.Errorf("parse bridge addr: %w", err)
	}
	if err := netlink.AddrAdd(br, addr); err != nil {
		// Ignore if address already exists
		if err.Error() != "file exists" {
			return nil, fmt.Errorf("add bridge addr: %w", err)
		}
	}

	// Bring up the bridge
	if err := netlink.LinkSetUp(br); err != nil {
		return nil, fmt.Errorf("set bridge up: %w", err)
	}

	return br, nil
}

// randomVethName generates a random veth interface name
func randomVethName() (string, error) {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("veth%x", b), nil
}

// SetupContainerNetwork sets up networking for a container
// pid is the container's init process PID
func SetupContainerNetwork(pid int, config NetworkConfig) (*Network, error) {
	if config.Mode == NetworkModeNone || config.Mode == NetworkModeHost {
		return &Network{config: config}, nil
	}

	if config.Mode != NetworkModeBridge {
		return nil, fmt.Errorf("unsupported network mode: %s", config.Mode)
	}

	bridgeName := config.Bridge
	if bridgeName == "" {
		bridgeName = DefaultBridgeName
	}

	// Ensure bridge exists
	br, err := EnsureBridge(bridgeName)
	if err != nil {
		return nil, err
	}

	// Generate random veth names
	hostVethName, err := randomVethName()
	if err != nil {
		return nil, fmt.Errorf("generate veth name: %w", err)
	}
	peerVethName, err := randomVethName()
	if err != nil {
		return nil, fmt.Errorf("generate peer veth name: %w", err)
	}

	// Create veth pair
	la := netlink.NewLinkAttrs()
	la.Name = hostVethName
	veth := &netlink.Veth{
		LinkAttrs: la,
		PeerName:  peerVethName,
	}

	if err := netlink.LinkAdd(veth); err != nil {
		return nil, fmt.Errorf("create veth pair: %w", err)
	}

	// Get the host side of the veth
	hostVeth, err := netlink.LinkByName(hostVethName)
	if err != nil {
		return nil, fmt.Errorf("get host veth: %w", err)
	}

	// Get the peer side of the veth
	peerVeth, err := netlink.LinkByName(peerVethName)
	if err != nil {
		netlink.LinkDel(hostVeth)
		return nil, fmt.Errorf("get peer veth: %w", err)
	}

	// Attach host veth to bridge
	if err := netlink.LinkSetMaster(hostVeth, br); err != nil {
		netlink.LinkDel(hostVeth)
		return nil, fmt.Errorf("attach to bridge: %w", err)
	}

	// Get container's network namespace
	nsPath := fmt.Sprintf("/proc/%d/ns/net", pid)
	containerNS, err := netns.GetFromPath(nsPath)
	if err != nil {
		netlink.LinkDel(hostVeth)
		return nil, fmt.Errorf("get container netns: %w", err)
	}

	// Move peer veth to container namespace
	if err := netlink.LinkSetNsFd(peerVeth, int(containerNS)); err != nil {
		containerNS.Close()
		netlink.LinkDel(hostVeth)
		return nil, fmt.Errorf("move veth to container: %w", err)
	}

	// Bring up host veth
	if err := netlink.LinkSetUp(hostVeth); err != nil {
		containerNS.Close()
		netlink.LinkDel(hostVeth)
		return nil, fmt.Errorf("set host veth up: %w", err)
	}

	// Configure the container side (in container namespace)
	if config.IPAddress != "" {
		if err := configureContainerInterface(containerNS, peerVethName, config); err != nil {
			containerNS.Close()
			netlink.LinkDel(hostVeth)
			return nil, fmt.Errorf("configure container interface: %w", err)
		}
	}

	return &Network{
		config:      config,
		bridge:      br,
		vethHost:    hostVeth,
		vethPeer:    peerVethName,
		containerNS: containerNS,
	}, nil
}

// configureContainerInterface configures the network interface inside the container
func configureContainerInterface(ns netns.NsHandle, ifName string, config NetworkConfig) error {
	// Lock OS thread to ensure namespace operations are consistent
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Save current namespace
	currentNS, err := netns.Get()
	if err != nil {
		return fmt.Errorf("get current netns: %w", err)
	}
	defer currentNS.Close()

	// Switch to container namespace
	if err := netns.Set(ns); err != nil {
		return fmt.Errorf("set netns: %w", err)
	}
	defer netns.Set(currentNS)

	// Get the interface
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("get interface: %w", err)
	}

	// Rename to eth0 for consistency
	if err := netlink.LinkSetName(link, "eth0"); err != nil {
		return fmt.Errorf("rename interface: %w", err)
	}

	// Get the renamed interface
	link, err = netlink.LinkByName("eth0")
	if err != nil {
		return fmt.Errorf("get eth0: %w", err)
	}

	// Add IP address
	addr, err := netlink.ParseAddr(config.IPAddress)
	if err != nil {
		return fmt.Errorf("parse IP: %w", err)
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("add IP: %w", err)
	}

	// Bring up the interface
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("set interface up: %w", err)
	}

	// Bring up loopback
	lo, err := netlink.LinkByName("lo")
	if err == nil {
		netlink.LinkSetUp(lo)
	}

	// Add default gateway
	if config.Gateway != "" {
		gw := net.ParseIP(config.Gateway)
		if gw == nil {
			return fmt.Errorf("invalid gateway: %s", config.Gateway)
		}
		route := &netlink.Route{
			Scope: netlink.SCOPE_UNIVERSE,
			Gw:    gw,
		}
		if err := netlink.RouteAdd(route); err != nil {
			return fmt.Errorf("add default route: %w", err)
		}
	}

	return nil
}

// Cleanup removes the network resources
func (n *Network) Cleanup() error {
	if n.containerNS != 0 {
		n.containerNS.Close()
	}
	if n.vethHost != nil {
		// Deleting host veth automatically deletes the peer
		return netlink.LinkDel(n.vethHost)
	}
	return nil
}

// WriteResolvConf writes /etc/resolv.conf in the container rootfs
func WriteResolvConf(rootfs string, dns []string) error {
	if len(dns) == 0 {
		// Use default DNS
		dns = []string{"8.8.8.8", "8.8.4.4"}
	}

	resolvPath := filepath.Join(rootfs, "etc", "resolv.conf")

	// Ensure etc directory exists
	if err := os.MkdirAll(filepath.Dir(resolvPath), 0755); err != nil {
		return err
	}

	var content string
	for _, server := range dns {
		content += fmt.Sprintf("nameserver %s\n", server)
	}

	return os.WriteFile(resolvPath, []byte(content), 0644)
}

// WriteHosts writes /etc/hosts in the container rootfs
func WriteHosts(rootfs, hostname, ipAddress string) error {
	hostsPath := filepath.Join(rootfs, "etc", "hosts")

	// Ensure etc directory exists
	if err := os.MkdirAll(filepath.Dir(hostsPath), 0755); err != nil {
		return err
	}

	ip := ipAddress
	if idx := len(ip) - 1; idx > 0 {
		// Remove CIDR suffix if present
		for i := len(ip) - 1; i >= 0; i-- {
			if ip[i] == '/' {
				ip = ip[:i]
				break
			}
		}
	}

	content := fmt.Sprintf(`127.0.0.1	localhost
::1		localhost ip6-localhost ip6-loopback
%s	%s
`, ip, hostname)

	return os.WriteFile(hostsPath, []byte(content), 0644)
}

// AllocateIP allocates the next available IP from a subnet
// This is a simple implementation - for production use a proper IPAM
func AllocateIP(subnet string, used []string) (string, error) {
	_, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return "", err
	}

	usedMap := make(map[string]bool)
	for _, ip := range used {
		usedMap[ip] = true
	}

	// Skip network address and gateway (first two IPs)
	ip := ipNet.IP.To4()
	if ip == nil {
		return "", fmt.Errorf("only IPv4 supported")
	}

	// Start from .2 (skip .0 network and .1 gateway)
	for i := 2; i < 255; i++ {
		candidate := fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], i)
		if !usedMap[candidate] {
			ones, _ := ipNet.Mask.Size()
			return fmt.Sprintf("%s/%d", candidate, ones), nil
		}
	}

	return "", fmt.Errorf("no available IPs in subnet")
}
