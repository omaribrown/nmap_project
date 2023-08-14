package scan

import (
	"context"
	"encoding/xml"
	"fmt"
	"go.uber.org/zap"
	"os/exec"
	"strconv"
	"sync"
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

// ScanClient represents a client for scanning ports
type ScanClient struct {
	Logger      *zap.Logger // Logger
	resultsLock sync.Mutex  // Mutex to protect scanResults slice
	DBClient    *DBClient   // Database client
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

// NewScanClient creates a new ScanClient
func NewScanClient(logger *zap.Logger, DBClient *DBClient) *ScanClient {
	return &ScanClient{
		Logger:   logger,
		DBClient: DBClient,
	}
}

// ScanPorts scans the ports for a list of IPs or hostnames
func (s *ScanClient) ScanPorts(ctx context.Context, request ScanRequestMapped) (interface{}, error) {
	s.Logger.Debug("scanning ports", zap.Any("request", request))
	// scan ports
	scanResults, err := s.scanRequestedHosts(ctx, request)
	if err != nil {
		s.Logger.Error("error scanning hosts", zap.Error(err))
		return nil, err
	}

	s.Logger.Debug("scan results", zap.Any("scanResults", scanResults))
	// check database for previous scans of hosts
	hostChanges, err := s.compareNewScanResults(ctx, scanResults)
	if err != nil {
		s.Logger.Error("error comparing scan results", zap.Error(err))
		return nil, err
	}

	s.Logger.Debug("host changes", zap.Any("hostChanges", hostChanges))

	// get historical scan results from database
	historicalScanData, err := s.getScanHistory(ctx, scanResults)
	if err != nil {
		s.Logger.Error("error getting historical scan data", zap.Error(err))
		return nil, err
	}

	s.Logger.Debug("historical scan data", zap.Any("historicalScanData", historicalScanData))

	// update database with new and updated ports
	err = s.updateScansDB(ctx, hostChanges)
	if err != nil {
		s.Logger.Error("error updating database", zap.Error(err))
		return nil, err
	}

	response := prepareResponse(scanResults, hostChanges, historicalScanData)

	return response, nil
}

// execScanCommand executes an NMap scan command for a single IP address.
func (s *ScanClient) execScanCommand(ctx context.Context, ip string, scanResults *[]ScanResult) {

	cmd := exec.CommandContext(ctx, "nmap", "-p", "0-1000", "--open", "--stats-every", "0", "-oX", "-", "-T5", ip)
	output, err := cmd.CombinedOutput()
	if err != nil {
		s.Logger.Warn("error running nmap command", zap.String("ip", ip))
		return
	}

	var nmapRun NmapRun
	if err := xml.Unmarshal(output, &nmapRun); err != nil {
		s.Logger.Warn("error unmarshaling nmap output", zap.Error(err))
		return
	}

	var results []ScanResult
	nmapStartTime, err := strconv.ParseInt(nmapRun.Start, 10, 64)
	if err != nil {
		s.Logger.Warn("error parsing start time", zap.Error(err))
		return
	}
	scanTime := time.Unix(nmapStartTime, 0)

	for _, host := range nmapRun.Hosts {
		var scanResult ScanResult
		scanResult.IP = host.Addresses[0].Addr
		if ip != scanResult.IP {
			scanResult.Host = ip
		}
		scanResult.ScanTime = scanTime
		scanResult.Ports = make(map[int]PortStatus) // Initialize the map here
		for _, port := range host.Ports {
			s.Logger.Debug("port", zap.Any("port", port))
			scanResult.Ports[port.PortID] = PortStatus(port.State.State)
		}

		results = append(results, scanResult)
	}

	// Append the results to scanResults
	*scanResults = append(*scanResults, results...)
}

// scanRequestedHosts scans the requested hosts
func (s *ScanClient) scanRequestedHosts(ctx context.Context, request ScanRequestMapped) ([]ScanResult, error) {
	var scanResults []ScanResult
	//var wg sync.WaitGroup
	// Loop through all ips and hostnames
	if len(request.IPs) > 0 {
		s.Logger.Debug("scanning ips", zap.Any("ips", request.IPs))
		for _, ip := range request.IPs {
			//wg.Add(1)
			s.execScanCommand(ctx, ip, &scanResults)

		}
	}

	if len(request.Hostnames) > 0 {
		s.Logger.Debug("scanning hostnames", zap.Any("hostnames", request.Hostnames))
		for _, host := range request.Hostnames {
			//wg.Add(1)
			s.execScanCommand(ctx, host, &scanResults)
		}
	}

	return scanResults, nil
}

// compareNewScanResults calls the database to see if there are any previous scans of the hosts, and if there are, it checks for differences in the results
func (s *ScanClient) compareNewScanResults(ctx context.Context, scans []ScanResult) ([]ScanResult, error) {
	// Get previous scan results from the database based on the host
	var listOfIPs []string
	for _, scan := range scans {
		listOfIPs = append(listOfIPs, scan.IP)
	}

	s.Logger.Debug("listOfIPs", zap.Any("listOfIPs", listOfIPs))
	queriedScans, err := s.DBClient.QueryByHost(ctx, listOfIPs)
	if err != nil {
		return nil, err
	}

	s.Logger.Debug("query results", zap.Any("queriedScans", queriedScans), zap.Any("scans", scans))

	// directly compare the results for differences
	hostChanges := compareHosts(scans, queriedScans)

	return hostChanges, nil
}

// updateScansDB updates the database with the new and updated ports
func (s *ScanClient) updateScansDB(ctx context.Context, scansToUpdate []ScanResult) error {
	for _, scan := range scansToUpdate {
		err := s.DBClient.UpsertScanResults(ctx, scan)
		if err != nil {
			return err
		}

		if err != nil {
			return err
		}
	}
	return nil
}

// getScanHistory should return the historical scan results for the hosts and ports associated
func (s *ScanClient) getScanHistory(ctx context.Context, scans []ScanResult) (interface{}, error) {
	var ipPortMap = make(map[string][]int)
	for _, scan := range scans {
		for port := range scan.Ports {
			ipPortMap[scan.IP] = append(ipPortMap[scan.IP], port)
		}
	}

	s.Logger.Debug("ipPortMap", zap.Any("ipPortMap", ipPortMap))

	// Query DB for historical scan results
	historicalScanData, err := s.DBClient.QueryByHostsAndPorts(ctx, ipPortMap)
	if err != nil {
		return nil, err
	}

	s.Logger.Debug("historicalScanData", zap.Any("historicalScanData", historicalScanData))
	return historicalScanData, nil
}

func compareHosts(results []ScanResult, queryResults []ScanResult) []ScanResult {
	var hostChanges []ScanResult

	// Map the current scan results to a map with the host as the key
	currentScanHostMap := make(map[string]ScanResult)
	for _, result := range results {
		currentScanHostMap[result.IP] = result
	}

	// Map the historical scan results to a map with the host as the key
	historicalScanHostMap := make(map[string]ScanResult)
	for _, result := range queryResults {
		historicalScanHostMap[result.IP] = result
	}

	// Compare the current and historical scans
	for currentKey, currentVal := range currentScanHostMap {
		historicalHostVal, ok := historicalScanHostMap[currentKey]
		if ok {
			// Initialize the Changes map
			currentVal.Changes = make(map[int]ChangeType)

			// Check for added or updated ports
			for currentPortNumber, currentPortStatus := range currentVal.Ports {
				historicalPortStatus, ok := historicalHostVal.Ports[currentPortNumber]
				if !ok {
					currentVal.Changes[currentPortNumber] = "added"
				} else if currentPortStatus != historicalPortStatus {
					currentVal.Changes[currentPortNumber] = "updated"
				}
			}

			// Check for removed ports
			for historicalPortNumber := range historicalHostVal.Ports {
				if _, ok := currentVal.Ports[historicalPortNumber]; !ok {
					currentVal.Changes[historicalPortNumber] = "removed"
				}
			}

			// Only append currentVal to hostChanges if there are changes
			if len(currentVal.Changes) > 0 {
				hostChanges = append(hostChanges, currentVal)
			}
		} else {
			// Handle case when there are no historical scan results for the host
			if currentVal.Changes == nil {
				currentVal.Changes = make(map[int]ChangeType)
			}
			for currentPortNumber := range currentVal.Ports {
				currentVal.Changes[currentPortNumber] = "added"
			}
			hostChanges = append(hostChanges, currentVal)
		}
	}
	fmt.Println("hostChanges", hostChanges)
	// if there are no changes, we still need to add a ScanResult for each host with an updated ScanTime
	if len(hostChanges) == 0 {
		for _, currentScan := range results {
			scanWithUpdatedTime := currentScan
			scanWithUpdatedTime.Changes = make(map[int]ChangeType)
			hostChanges = append(hostChanges, scanWithUpdatedTime)
		}
	}

	return hostChanges
}

func prepareResponse(scanResults []ScanResult, hostChanges []ScanResult, historicalScanData interface{}) interface{} {
	// Combine the latest scan results with the detected changes
	for i, scan := range scanResults {
		for _, change := range hostChanges {
			if scan.Host == change.Host {
				scanResults[i].Changes = change.Changes
				break
			}
		}
	}

	// combine the scan results and historical scan data into a single struct
	response := struct {
		ScanResults        []ScanResult `json:"scan_results"`
		HistoricalScanData interface{}  `json:"historical_scan_data"`
	}{
		ScanResults:        scanResults,
		HistoricalScanData: historicalScanData,
	}

	return response
}
