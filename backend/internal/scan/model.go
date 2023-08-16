package scan

import "time"

// ScanRequest represents a request to scan a list of IPs or hostnames
type ScanRequest struct {
	IPsOrHostnames []string `json:"ips_or_hostnames" validate:"required"` // List of IPs or hostnames to scan
}

// ScanRequestMapped represents a mapped version of ScanRequest
type ScanRequestMapped struct {
	IPs       []string `validate:"dive,ip"`   // List of IPs to scan
	Hostnames []string `validate:"dive,fqdn"` // List of hostnames to scan
}

// NMapScanPorts represents the ports to scan with NMap
type NMapScanPorts struct {
	HostnameIPMap map[string]string // Map of hostname to IP address
}

// NmapRun represents the output of an NMap scan
type NmapRun struct {
	Start string     `xml:"start,attr"` // Start time of the scan
	Hosts []NmapHost `xml:"host"`       // List of hosts scanned
}

// NmapHost represents a scanned host
type NmapHost struct {
	Addresses []Address `xml:"address"`    // List of addresses for the host
	Ports     []Port    `xml:"ports>port"` // List of ports for the host
}

// Address represents an address for a host
type Address struct {
	Addr string `xml:"addr,attr"` // Address
}

// Port represents a port for a host
type Port struct {
	Protocol string `xml:"protocol,attr"` // Protocol
	PortID   int    `xml:"portid,attr"`   // Port number
	State    State  `xml:"state"`         // State of the port
}

// State represents the state of a port
type State struct {
	State string `xml:"state,attr"` // State
}

type Host struct {
	HostID    string `db:"host_id" json:"host_id,omitempty"`
	IPAddress string `db:"ip_address" json:"ip_address"`
	Hostname  string `db:"hostname" json:"hostname"`
}

type ScanResult struct {
	ScanID    string    `db:"scan_id" json:"scan_id,omitempty"`
	IPAddress string    `db:"ip_address" json:"ip_address"`
	Timestamp time.Time `db:"timestamp" json:"timestamp"`
	Port      int       `db:"port" json:"port"`
	Status    string    `db:"status" json:"status"`
}

type ScanResponse struct {
	Host        Host           `json:"host"`
	ScanResults []*ScanResult  `json:"scan_results"`
	PortHistory []*ScanResult  `json:"port_history"`
	Changes     map[int]string `json:"changes,omitempty"`
}
