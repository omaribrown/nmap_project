package scan

import (
	"time"
)

// PortStatus represents the status of a port
type PortStatus string

// ChangeType represents the type of change made to a port
type ChangeType string

// ScanResult represents the result of a port scan
type ScanResult struct {
	Host     string             `json:"host" db:"host"`           // Host url submitted by the user
	IP       string             `json:"ip" db:"ip"`               // IP address of the host
	ScanTime time.Time          `json:"scan_time" db:"scan_time"` // Time the scan was performed
	Ports    map[int]PortStatus `json:"ports"`                    // Map of port number to port status
	Changes  map[int]ChangeType `json:"changes,omitempty"`        // Map of port number to change type (only included if there are changes)
}

// PortResult represents the result of a port scan for a single port
type PortResult struct {
	PortNumber int        `json:"port_number" db:"port_number"` // Port number
	Status     PortStatus `json:"status" db:"status"`           // Port status
}

// PortChange represents a change made to a port
type PortChange struct {
	PortNumber int        `json:"port_number" db:"port_number"` // Port number
	Change     ChangeType `json:"change" db:"change_type"`      // Type of change made to the port (e.g., "added", "removed", "updated")
}

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

// ScanTimeStatus represents the status of a scan at a specific time
type ScanTimeStatus struct {
	Time   time.Time `json:"time"`   // Time of the scan
	Status string    `json:"status"` // Status of the scan
}

// PortHistory represents the history of a port
type PortHistory struct {
	PortNumber int              `json:"port_number"` // Port number
	History    []ScanTimeStatus `json:"history"`     // List of scan times and statuses
}

// IPHistory represents the history of an IP address
type IPHistory struct {
	IP   string        `json:"ip"`   // IP address
	Port []PortHistory `json:"port"` // List of port histories
}

// HistoricalScanData represents the historical scan data for a list of IPs
type HistoricalScanData struct {
	Data []IPHistory `json:"ip_scan_history"` // List of IP histories
}

// NmapRun represents the output of an NMap scan
type NmapRun struct {
	Start string `xml:"start,attr"` // Start time of the scan
	Hosts []Host `xml:"host"`       // List of hosts scanned
}

// Host represents a scanned host
type Host struct {
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
