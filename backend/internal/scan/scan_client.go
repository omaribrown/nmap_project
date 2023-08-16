package scan

import (
	"context"
	"encoding/xml"
	"fmt"
	"go.uber.org/zap"
	"os/exec"
	"strconv"
	"time"
)

// ScanClient represents a client for scanning ports
type ScanClient struct {
	Logger   *zap.Logger // Logger
	DBClient *DBClient   // Database client
}

// NewScanClient creates a new ScanClient
func NewScanClient(logger *zap.Logger, DBClient *DBClient) *ScanClient {
	return &ScanClient{
		Logger:   logger,
		DBClient: DBClient,
	}
}

func (s *ScanClient) ScanForOpenPorts(ctx context.Context, request ScanRequestMapped) (*ScanResponse, error) {
	var host Host
	if len(request.IPs) > 0 {
		host.IPAddress = request.IPs[0]
	} else {
		host.Hostname = request.Hostnames[0]
	}

	// Scan the host using NMap cli
	scannedHost, scannedPorts, err := s.execScanCommand(ctx, host)
	if err != nil {
		s.Logger.Error("error running nmap command", zap.Any("host", host))
		return nil, fmt.Errorf("error running nmap command for host %s", host.IPAddress)
	}

	if len(scannedPorts) == 0 {
		s.Logger.Error("no ports found", zap.Any("host", host))
		return nil, fmt.Errorf("no ports found for host %s", host.IPAddress)
	}

	s.Logger.Debug("Scanned Host", zap.Any("scannedHost", scannedHost), zap.Any("scannedPorts", scannedPorts))

	// Get the port history from the database
	portHistory, err := s.DBClient.QueryPortHistory(ctx, scannedHost.IPAddress, scannedPorts)
	if err != nil {
		s.Logger.Error("error querying port history", zap.Error(err))
		return nil, fmt.Errorf("error querying port history for host %s", host.IPAddress)
	}

	s.Logger.Debug("Port History", zap.Any("portHistory", portHistory))

	// Check the newest scanned host's ports against the port last scan
	changedPorts := comparePorts(scannedPorts, portHistory)

	s.Logger.Debug("Changed Ports", zap.Any("changedPorts", changedPorts))

	// Update the database with the new and updated ports
	err = s.DBClient.UpsertScanResults(ctx, scannedHost, scannedPorts)
	if err != nil {
		s.Logger.Error("error updating database", zap.Error(err))
		return nil, fmt.Errorf("error updating database for host %s", host.IPAddress)
	}

	s.Logger.Debug("Updated Database with new and updated ports")

	// Return the ports & changes
	response := &ScanResponse{
		ScanResults: scannedPorts,
		Changes:     changedPorts,
		Host:        scannedHost,
		PortHistory: portHistory,
	}

	s.Logger.Debug("Response", zap.Any("response", response))

	return response, nil
}

// comparePorts compares the ports of the newest scan against the last scan and returns a map where the key is the port number and the value is the change type (added, removed)
func comparePorts(scannedPorts []*ScanResult, portHistory []*ScanResult) map[int]string {
	// For each port in scannedPorts, we need to get the latest port status from portHistory if it exists
	// portHistory may have multiple entries for each port, so we need to get the latest one
	// If it doesn't exist, then we know it's a new port
	// If it does exist, then we need to compare the status of the port in scannedPorts to the status of the port in portHistory
	// If the status is different, then we know the port has been updated
	// If the status is the same, then we know the port has not changed

	// Create a map of the newest scan's ports
	scannedPortsMap := make(map[int]string)
	for _, port := range scannedPorts {
		scannedPortsMap[port.Port] = port.Status
	}

	// Iterate through portHistory to find the latest port status for each port
	// Create a map of the last scan's ports
	portHistoryMap := make(map[int]string)
	for _, portScan := range portHistory {
		if _, ok := portHistoryMap[portScan.Port]; !ok {
			portHistoryMap[portScan.Port] = portScan.Status
		}
	}

	// Compare the two maps and return a map of the changes where if the port was added or removed, the value is "added" or "removed", respectively
	changedPorts := make(map[int]string)
	for port := range scannedPortsMap {
		// Check if the port exists in the portHistoryMap
		if _, ok := portHistoryMap[port]; !ok {
			changedPorts[port] = "added"
		}
	}

	// Check if the any of the ports in the portHistoryMap have been removed
	for port := range portHistoryMap {
		// Check if the port exists in the scannedPortsMap
		if _, ok := scannedPortsMap[port]; !ok {
			changedPorts[port] = "removed"
		}
	}

	return changedPorts
}

// execScanCommand executes an NMap scan command for a single IP address.
func (s *ScanClient) execScanCommand(ctx context.Context, host Host) (Host, []*ScanResult, error) {
	var scanParam string
	var scanResults []*ScanResult

	if host.Hostname != "" {
		scanParam = host.Hostname
	} else {
		scanParam = host.IPAddress
	}

	cmd := exec.CommandContext(ctx, "nmap", "-p", "0-1000", "--open", "--stats-every", "0", "-oX", "-", "-T5", scanParam)
	output, err := cmd.CombinedOutput()
	if err != nil {
		s.Logger.Error("error running nmap command", zap.Any("host", host))
		return host, nil, err
	}

	var nmapRun NmapRun
	if err := xml.Unmarshal(output, &nmapRun); err != nil {
		s.Logger.Error("error unmarshaling nmap output", zap.Error(err))
		return host, nil, err
	}

	//var results []ScanResult
	nmapStartTime, err := strconv.ParseInt(nmapRun.Start, 10, 64)
	if err != nil {
		s.Logger.Error("error parsing start time", zap.Error(err))
		return host, nil, err
	}
	scanTime := time.Unix(nmapStartTime, 0)

	for _, h := range nmapRun.Hosts {
		if host.IPAddress != h.Addresses[0].Addr {
			host.IPAddress = h.Addresses[0].Addr
		}

		for _, port := range h.Ports {
			s.Logger.Debug("Port", zap.Any("port", port))
			scanResults = append(scanResults, &ScanResult{
				IPAddress: host.IPAddress,
				Timestamp: scanTime,
				Port:      port.PortID,
				Status:    port.State.State,
			})
		}

	}
	return host, scanResults, nil
}
