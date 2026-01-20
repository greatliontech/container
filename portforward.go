package container

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// PortMapping defines a port forwarding rule
type PortMapping struct {
	// HostIP is the host IP to bind to (empty for all interfaces)
	HostIP string
	// HostPort is the port on the host
	HostPort uint16
	// ContainerPort is the port in the container
	ContainerPort uint16
	// Protocol is "tcp" or "udp"
	Protocol string
}

// PortForwarder manages port forwarding rules using nftables
type PortForwarder struct {
	conn        *nftables.Conn
	table       *nftables.Table
	prerouting  *nftables.Chain
	postrouting *nftables.Chain
	containerIP net.IP
	mappings    []PortMapping
}

const (
	tableNameContainer = "container_nat"
)

// NewPortForwarder creates a new port forwarder for a container
func NewPortForwarder(containerIP string, bridge string) (*PortForwarder, error) {
	ip := net.ParseIP(containerIP)
	if ip == nil {
		return nil, fmt.Errorf("invalid container IP: %s", containerIP)
	}
	ip = ip.To4()
	if ip == nil {
		return nil, fmt.Errorf("only IPv4 supported: %s", containerIP)
	}

	conn, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("nftables conn: %w", err)
	}

	pf := &PortForwarder{
		conn:        conn,
		containerIP: ip,
	}

	if err := pf.ensureTable(); err != nil {
		return nil, err
	}

	return pf, nil
}

func (pf *PortForwarder) ensureTable() error {
	// Check if table exists
	tables, err := pf.conn.ListTables()
	if err != nil {
		return fmt.Errorf("list tables: %w", err)
	}

	for _, t := range tables {
		if t.Name == tableNameContainer && t.Family == nftables.TableFamilyIPv4 {
			pf.table = t
			break
		}
	}

	// Create table if it doesn't exist
	if pf.table == nil {
		pf.table = &nftables.Table{
			Family: nftables.TableFamilyIPv4,
			Name:   tableNameContainer,
		}
		pf.conn.AddTable(pf.table)
	}

	// Get or create prerouting chain (for DNAT)
	chains, err := pf.conn.ListChains()
	if err != nil {
		return fmt.Errorf("list chains: %w", err)
	}

	for _, c := range chains {
		if c.Table.Name == tableNameContainer {
			if c.Name == "prerouting" {
				pf.prerouting = c
			} else if c.Name == "postrouting" {
				pf.postrouting = c
			}
		}
	}

	if pf.prerouting == nil {
		pf.prerouting = &nftables.Chain{
			Name:     "prerouting",
			Table:    pf.table,
			Type:     nftables.ChainTypeNAT,
			Hooknum:  nftables.ChainHookPrerouting,
			Priority: nftables.ChainPriorityNATDest,
		}
		pf.conn.AddChain(pf.prerouting)
	}

	if pf.postrouting == nil {
		pf.postrouting = &nftables.Chain{
			Name:     "postrouting",
			Table:    pf.table,
			Type:     nftables.ChainTypeNAT,
			Hooknum:  nftables.ChainHookPostrouting,
			Priority: nftables.ChainPriorityNATSource,
		}
		pf.conn.AddChain(pf.postrouting)
	}

	if err := pf.conn.Flush(); err != nil {
		return fmt.Errorf("flush table setup: %w", err)
	}

	return nil
}

// AddMapping adds a port mapping
func (pf *PortForwarder) AddMapping(mapping PortMapping) error {
	if mapping.Protocol == "" {
		mapping.Protocol = "tcp"
	}

	proto := unix.IPPROTO_TCP
	if mapping.Protocol == "udp" {
		proto = unix.IPPROTO_UDP
	}

	// DNAT rule: redirect incoming traffic on HostPort to container
	dnatExprs := []expr.Any{
		// Load IP protocol
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{byte(proto)},
		},
		// Load destination port
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       2, // Destination port offset
			Len:          2,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryPort(mapping.HostPort),
		},
		// DNAT to container IP:port
		&expr.Immediate{
			Register: 1,
			Data:     pf.containerIP.To4(),
		},
		&expr.Immediate{
			Register: 2,
			Data:     binaryPort(mapping.ContainerPort),
		},
		&expr.NAT{
			Type:        expr.NATTypeDestNAT,
			Family:      unix.NFPROTO_IPV4,
			RegAddrMin:  1,
			RegProtoMin: 2,
		},
	}

	pf.conn.AddRule(&nftables.Rule{
		Table: pf.table,
		Chain: pf.prerouting,
		Exprs: dnatExprs,
		UserData: []byte(fmt.Sprintf("dnat:%d:%d:%s",
			mapping.HostPort, mapping.ContainerPort, mapping.Protocol)),
	})

	// MASQUERADE rule for return traffic (hairpin NAT)
	masqExprs := []expr.Any{
		// Match protocol
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{byte(proto)},
		},
		// Match destination IP (container)
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       16, // Destination IP offset in IPv4 header
			Len:          4,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     pf.containerIP.To4(),
		},
		// Match destination port
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       2,
			Len:          2,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryPort(mapping.ContainerPort),
		},
		// MASQUERADE
		&expr.Masq{},
	}

	pf.conn.AddRule(&nftables.Rule{
		Table: pf.table,
		Chain: pf.postrouting,
		Exprs: masqExprs,
		UserData: []byte(fmt.Sprintf("masq:%d:%d:%s",
			mapping.HostPort, mapping.ContainerPort, mapping.Protocol)),
	})

	if err := pf.conn.Flush(); err != nil {
		return fmt.Errorf("flush rules: %w", err)
	}

	pf.mappings = append(pf.mappings, mapping)
	return nil
}

// RemoveMapping removes a port mapping
func (pf *PortForwarder) RemoveMapping(mapping PortMapping) error {
	if mapping.Protocol == "" {
		mapping.Protocol = "tcp"
	}

	// Find and delete rules with matching user data
	dnatUD := fmt.Sprintf("dnat:%d:%d:%s", mapping.HostPort, mapping.ContainerPort, mapping.Protocol)
	masqUD := fmt.Sprintf("masq:%d:%d:%s", mapping.HostPort, mapping.ContainerPort, mapping.Protocol)

	rules, err := pf.conn.GetRules(pf.table, pf.prerouting)
	if err == nil {
		for _, r := range rules {
			if string(r.UserData) == dnatUD {
				pf.conn.DelRule(r)
			}
		}
	}

	rules, err = pf.conn.GetRules(pf.table, pf.postrouting)
	if err == nil {
		for _, r := range rules {
			if string(r.UserData) == masqUD {
				pf.conn.DelRule(r)
			}
		}
	}

	if err := pf.conn.Flush(); err != nil {
		return fmt.Errorf("flush delete: %w", err)
	}

	// Remove from tracked mappings
	for i, m := range pf.mappings {
		if m.HostPort == mapping.HostPort && m.Protocol == mapping.Protocol {
			pf.mappings = append(pf.mappings[:i], pf.mappings[i+1:]...)
			break
		}
	}

	return nil
}

// Cleanup removes all port forwarding rules for this container
func (pf *PortForwarder) Cleanup() error {
	// Delete all rules we created
	for _, mapping := range pf.mappings {
		pf.RemoveMapping(mapping)
	}
	pf.mappings = nil

	// Note: We don't delete the table/chains as other containers may be using them
	return nil
}

// binaryPort converts a port to network byte order
func binaryPort(port uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, port)
	return b
}

// EnsureForwardingEnabled ensures IP forwarding is enabled
func EnsureForwardingEnabled() error {
	// Read current value
	data, err := readProc("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		return err
	}
	if strings.TrimSpace(data) == "1" {
		return nil
	}

	// Enable forwarding by writing to procfs
	return writeProc("/proc/sys/net/ipv4/ip_forward", "1")
}

func readProc(path string) (string, error) {
	fd, err := unix.Open(path, unix.O_RDONLY, 0)
	if err != nil {
		return "", err
	}
	defer unix.Close(fd)
	buf := make([]byte, 64)
	n, err := unix.Read(fd, buf)
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}

func writeProc(path, value string) error {
	fd, err := unix.Open(path, unix.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	_, err = unix.Write(fd, []byte(value))
	return err
}

// SetupNATForBridge sets up NAT for a bridge network using nftables
func SetupNATForBridge(bridge string, subnet string) error {
	if bridge == "" {
		bridge = DefaultBridgeName
	}

	// Ensure forwarding is enabled
	if err := EnsureForwardingEnabled(); err != nil {
		return fmt.Errorf("enable forwarding: %w", err)
	}

	conn, err := nftables.New()
	if err != nil {
		return err
	}

	// Create/get table
	table := &nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   tableNameContainer,
	}
	conn.AddTable(table)

	// Create postrouting chain for MASQUERADE
	postrouting := &nftables.Chain{
		Name:     "postrouting",
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
	}
	conn.AddChain(postrouting)

	// Parse subnet
	_, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return fmt.Errorf("parse subnet: %w", err)
	}

	// MASQUERADE rule for outgoing traffic from subnet (not going to bridge)
	masqExprs := []expr.Any{
		// Match source IP in subnet
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       12, // Source IP offset
			Len:          4,
		},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           ipNet.Mask,
			Xor:            []byte{0, 0, 0, 0},
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ipNet.IP.To4(),
		},
		// Exclude traffic going out bridge interface
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpNeq,
			Register: 1,
			Data:     padString(bridge, 16),
		},
		// MASQUERADE
		&expr.Masq{},
	}

	conn.AddRule(&nftables.Rule{
		Table:    table,
		Chain:    postrouting,
		Exprs:    masqExprs,
		UserData: []byte("bridge_masq:" + bridge),
	})

	// Create forward chain to allow traffic
	forward := &nftables.Chain{
		Name:     "forward",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
	}
	conn.AddChain(forward)

	// Allow forwarding to/from bridge
	for _, dir := range []expr.MetaKey{expr.MetaKeyIIFNAME, expr.MetaKeyOIFNAME} {
		conn.AddRule(&nftables.Rule{
			Table: table,
			Chain: forward,
			Exprs: []expr.Any{
				&expr.Meta{Key: dir, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     padString(bridge, 16),
				},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
			UserData: []byte("bridge_forward:" + bridge),
		})
	}

	return conn.Flush()
}

// padString pads a string to the specified length with null bytes
func padString(s string, length int) []byte {
	b := make([]byte, length)
	copy(b, s)
	return b
}

// ParsePortMapping parses a port mapping string like "8080:80" or "8080:80/tcp"
func ParsePortMapping(s string) (PortMapping, error) {
	mapping := PortMapping{Protocol: "tcp"}

	// Check for protocol suffix
	if idx := strings.LastIndex(s, "/"); idx != -1 {
		mapping.Protocol = s[idx+1:]
		s = s[:idx]
	}

	// Split host:container
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return mapping, fmt.Errorf("invalid port mapping: %s", s)
	}

	hostPort, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil {
		return mapping, fmt.Errorf("invalid host port: %s", parts[0])
	}
	mapping.HostPort = uint16(hostPort)

	containerPort, err := strconv.ParseUint(parts[1], 10, 16)
	if err != nil {
		return mapping, fmt.Errorf("invalid container port: %s", parts[1])
	}
	mapping.ContainerPort = uint16(containerPort)

	return mapping, nil
}

// PortMappingsFromStrings parses multiple port mapping strings
func PortMappingsFromStrings(ss []string) ([]PortMapping, error) {
	var mappings []PortMapping
	for _, s := range ss {
		m, err := ParsePortMapping(s)
		if err != nil {
			return nil, err
		}
		mappings = append(mappings, m)
	}
	return mappings, nil
}
