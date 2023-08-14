package scan

import (
	"testing"
	"time"
)

func Test_compareHosts(t *testing.T) {
	scanTime := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	oldScanTime := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	type args struct {
		results      []ScanResult
		queryResults []ScanResult
	}
	tests := []struct {
		name string
		args args
		want []ScanResult
	}{
		{
			name: "Test Case 1: No Changes",
			args: args{
				results: []ScanResult{
					{IP: "1234", Ports: map[int]PortStatus{80: "open"}, ScanTime: scanTime},
				},
				queryResults: []ScanResult{
					{IP: "1234", Ports: map[int]PortStatus{80: "open"}, ScanTime: oldScanTime},
				},
			},
			want: []ScanResult{
				{IP: "12234", Ports: map[int]PortStatus{80: "open"}, ScanTime: scanTime},
			},
		},
		{
			name: "Test Case 2: Port Added",
			args: args{
				results: []ScanResult{
					{Host: "host1", Ports: map[int]PortStatus{80: "open", 443: "open"}},
				},
				queryResults: []ScanResult{
					{Host: "host1", Ports: map[int]PortStatus{80: "open"}},
				},
			},
			want: []ScanResult{
				{Host: "host1", Ports: map[int]PortStatus{80: "open", 443: "open"}, Changes: map[int]ChangeType{443: "added"}},
			},
		},
		{
			name: "Test Case 3: Port Removed",
			args: args{
				results: []ScanResult{
					{Host: "host1", Ports: map[int]PortStatus{80: "open"}},
				},
				queryResults: []ScanResult{
					{Host: "host1", Ports: map[int]PortStatus{80: "open", 443: "open"}},
				},
			},
			want: []ScanResult{
				{Host: "host1", Ports: map[int]PortStatus{80: "open"}, Changes: map[int]ChangeType{443: "removed"}},
			},
		},
		{
			name: "Test Case 4: Port Changed",
			args: args{
				results: []ScanResult{
					{Host: "host1", Ports: map[int]PortStatus{80: "closed"}},
				},
				queryResults: []ScanResult{
					{Host: "host1", Ports: map[int]PortStatus{80: "open"}},
				},
			},
			want: []ScanResult{
				{Host: "host1", Ports: map[int]PortStatus{80: "closed"}, Changes: map[int]ChangeType{80: "updated"}},
			},
		},
		{
			name: "Test Case 5: Multiple Ports Added, Removed, and Changed",
			args: args{
				results: []ScanResult{
					{Host: "host1", Ports: map[int]PortStatus{80: "closed", 443: "open", 8080: "open"}},
				},
				queryResults: []ScanResult{
					{Host: "host1", Ports: map[int]PortStatus{80: "open", 443: "closed", 9090: "open"}},
				},
			},
			want: []ScanResult{
				{Host: "host1", Ports: map[int]PortStatus{80: "closed", 443: "open", 8080: "open"}, Changes: map[int]ChangeType{80: "updated", 443: "updated", 8080: "added", 9090: "removed"}},
			},
		},
		{
			name: "Test Case 6: No Query Results",
			args: args{
				results: []ScanResult{
					{Host: "host1", Ports: map[int]PortStatus{80: "closed", 443: "open", 8080: "open"}},
				},
				queryResults: []ScanResult{},
			},
			want: []ScanResult{
				{Host: "host1", Ports: map[int]PortStatus{80: "closed", 443: "open", 8080: "open"}, Changes: map[int]ChangeType{80: "added", 443: "added", 8080: "added"}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := compareHosts(tt.args.results, tt.args.queryResults); len(got) != len(tt.want) {
				t.Errorf("compareHosts() length = %v, want %v", len(got), len(tt.want))
			}
		})
	}
}
