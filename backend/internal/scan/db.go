package scan

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"go.uber.org/zap"
)

// IDBClient is an interface that defines the methods for interacting with the database.
type IDBClient interface {
	QueryByHost(ctx context.Context, IPs []string) ([]ScanResult, error)
	InsertScanResults(ctx context.Context, scan ScanResult) error
	UpdateScanResults(ctx context.Context, scan ScanResult) error
	HostExists(ctx context.Context, host string) (bool, error)
	QueryByHostsAndPorts(ctx context.Context, ipAndPorts map[string][]int) (*HistoricalScanData, error)
	UpsertScanResults(ctx context.Context, scan ScanResult) error
}

// DBClient is a struct that implements the IDBClient interface.
type DBClient struct {
	DB     *sql.DB
	Logger *zap.Logger
}

// NewDBClient creates a new instance of DBClient and returns a pointer to it.
func NewDBClient(connectionString string, logger *zap.Logger) *DBClient {
	conn, err := sql.Open("mysql", connectionString)
	if err != nil {
		panic(fmt.Sprintf("error opening connection to database: %s", err.Error()))
	}

	// ping the database to ensure the connection is valid
	err = conn.Ping()
	if err != nil {
		panic(fmt.Sprintf("error pinging database: %s", err.Error()))
	}

	return &DBClient{
		DB:     conn,
		Logger: logger,
	}
}

// QueryByHost retrieves scan results for a given list of IPs.
func (db *DBClient) QueryByHost(ctx context.Context, IPs []string) ([]ScanResult, error) {
	if len(IPs) == 0 {
		return nil, errors.New("no IPs provided")
	}

	// Create placeholders and arguments for the IN clause
	placeholders := make([]string, len(IPs))
	args := make([]interface{}, len(IPs))
	for i, IP := range IPs {
		placeholders[i] = "?"
		args[i] = IP
	}

	db.Logger.Debug("placeholders", zap.Any("placeholders", placeholders), zap.Any("args", args))

	// Build the query
	query := fmt.Sprintf(`
		SELECT ip, scan_time, scan_id
		FROM scan_results
		WHERE ip IN (%s)
	`, strings.Join(placeholders, ", "))

	db.Logger.Debug("query", zap.Any("query", query))
	rows, err := db.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("error executing query: %w", err)
	}

	defer rows.Close()

	db.Logger.Debug("rows", zap.Any("rows", rows))
	var results []ScanResult
	for rows.Next() {
		var result ScanResult
		var scanTimeStr string
		var scanID int64
		err := rows.Scan(&result.IP, &scanTimeStr, &scanID)
		if err != nil {
			return nil, fmt.Errorf("error scanning row: %w", err)
		}

		result.ScanTime, err = time.Parse("2006-01-02 15:04:05", scanTimeStr)
		if err != nil {
			return nil, fmt.Errorf("error parsing scan time: %w", err)
		}

		db.Logger.Debug("result: ", zap.Any("result", result), zap.Any("scanID", scanID))
		// Retrieve Ports for this host
		portQuery := "SELECT port_number, status FROM port_results WHERE scan_id = ?"
		portRows, err := db.DB.QueryContext(ctx, portQuery, scanID)
		if err != nil {
			return nil, fmt.Errorf("error executing port query: %w", err)
		}

		db.Logger.Debug("portRows", zap.Any("portRows", portRows))
		result.Ports = make(map[int]PortStatus)

		for portRows.Next() {
			var portNumber int
			var status string
			err := portRows.Scan(&portNumber, &status)
			if err != nil {
				return nil, fmt.Errorf("error scanning port row: %w", err)
			}
			result.Ports[portNumber] = PortStatus(status)
			db.Logger.Debug("port", zap.Any("port", portNumber), zap.Any("status", status))
		}

		// Retrieve Changes for the port map's keys
		result.Changes = make(map[int]ChangeType)
		changePlaceholders := make([]string, len(result.Ports))
		changeArgs := make([]interface{}, len(result.Ports))
		i := 0
		for portNumber := range result.Ports {
			changePlaceholders[i] = "?"
			changeArgs[i] = portNumber
			i++
		}

		db.Logger.Debug("changePlaceholders", zap.Any("changePlaceholders", changePlaceholders), zap.Any("changeArgs", changeArgs))

		changeQuery := fmt.Sprintf(`
	SELECT pc.change_type, pr.port_number
	FROM port_changes AS pc
	JOIN port_results AS pr ON pc.port_id = pr.port_id
	WHERE pr.port_number IN (%s) AND pr.scan_id = ?
`, strings.Join(changePlaceholders, ", "))

		// Add the scanID to the changeArgs slice
		changeArgs = append(changeArgs, scanID)

		changeRows, err := db.DB.QueryContext(ctx, changeQuery, changeArgs...)
		if err != nil {
			return nil, fmt.Errorf("error executing change query: %w", err)
		}

		db.Logger.Debug("changeRows", zap.Any("changeRows", changeRows))

		for changeRows.Next() {
			var change string
			var portNumber int
			err := changeRows.Scan(&change, &portNumber)
			if err != nil {
				return nil, fmt.Errorf("error scanning change row: %w", err)
			}
			result.Changes[portNumber] = ChangeType(change)
		}

		results = append(results, result)
		db.Logger.Info("results", zap.Any("results", results))
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error reading rows: %w", err)
	}

	return results, nil
}

// InsertScanResults inserts scan results into the database.
func (db *DBClient) InsertScanResults(ctx context.Context, scan ScanResult) error {
	tx, err := db.DB.Begin()
	if err != nil {
		return err
	}

	// Insert into scan_results table
	var res sql.Result
	var insertQuery string
	if scan.Host != "" {
		insertQuery = `INSERT INTO scan_results (ip, host, scan_time) VALUES (?, ?, ?)`
		res, err = tx.ExecContext(ctx, insertQuery, scan.IP, scan.Host, scan.ScanTime)
	} else {
		insertQuery = `INSERT INTO scan_results (ip, scan_time) VALUES (?, ?)`
		res, err = tx.ExecContext(ctx, insertQuery, scan.IP, scan.ScanTime)
	}
	if err != nil {
		tx.Rollback()
		return err
	}

	scanID, err := res.LastInsertId()
	if err != nil {
		tx.Rollback()
		return err
	}

	// Insert individual port results
	for port, status := range scan.Ports {
		portRes, err := tx.ExecContext(ctx, `INSERT INTO port_results (scan_id, port_number, status) VALUES (?, ?, ?)`, scanID, port, string(status))
		if err != nil {
			tx.Rollback()
			return err
		}

		portID, err := portRes.LastInsertId()
		if err != nil {
			tx.Rollback()
			return err
		}

		// Insert port changes if they exist
		if change, exists := scan.Changes[port]; exists {
			_, err = tx.ExecContext(ctx, `INSERT INTO port_changes (port_id, change_type, scan_time) VALUES (?, ?, ?)`, portID, string(change), scan.ScanTime)
			if err != nil {
				tx.Rollback()
				return err
			}
		}

		// Insert port scan history
		_, err = tx.ExecContext(ctx, `INSERT INTO port_scan_history (port_id, scan_time, status) VALUES (?, ?, ?)`, portID, scan.ScanTime, string(status))
		if err != nil {
			tx.Rollback()
			return err
		}

		db.Logger.Debug("Inserted scan history", zap.Any("portID", portID), zap.Any("scanTime", scan.ScanTime), zap.Any("status", string(status)))

	}

	return tx.Commit()
}

func (db *DBClient) UpdateScanResults(ctx context.Context, scan ScanResult) error {
	tx, err := db.DB.Begin()
	if err != nil {
		return err
	}

	// Query to get the scan_id based on the host
	var scanID int64
	err = tx.QueryRowContext(ctx, `SELECT scan_id FROM scan_results WHERE host = ?`, scan.Host).Scan(&scanID)
	if err != nil {
		tx.Rollback()
		return err
	}

	db.Logger.Debug("scanID", zap.Any("scanID", scanID))

	// Update the main scan_results table
	_, err = tx.ExecContext(ctx, `UPDATE scan_results SET scan_time = ? WHERE scan_id = ?`, scan.ScanTime, scanID)
	if err != nil {
		tx.Rollback()
		return err
	}

	db.Logger.Debug("scanTime", zap.Any("scanTime", scan.ScanTime))

	// Update individual port results and port changes
	for port, status := range scan.Ports {
		// Retrieve the portID, or calculate it as needed
		var portID int64
		err = tx.QueryRowContext(ctx, `SELECT port_id FROM port_results WHERE scan_id = ? AND port_number = ?`, scanID, port).Scan(&portID)
		if err != nil {
			tx.Rollback()
			return err
		}

		db.Logger.Debug("portID", zap.Any("portID", portID))

		// Update port result
		_, err = tx.ExecContext(ctx, `UPDATE port_results SET status = ? WHERE port_id = ?`, string(status), portID)
		if err != nil {
			tx.Rollback()
			return err
		}

		db.Logger.Debug("portStatus", zap.Any("portStatus", string(status)))

		// Insert port changes if any
		for _, change := range scan.Changes {
			_, err = tx.ExecContext(ctx, `INSERT INTO port_changes (port_id, change_type) VALUES (?, ?)`, portID, string(change))
			if err != nil {
				tx.Rollback()
				return err
			}

			db.Logger.Debug("change", zap.Any("change", string(change)))
		}

		// Insert port scan history
		_, err = tx.ExecContext(ctx, `INSERT INTO port_scan_history (port_id, scan_time, status) VALUES (?, ?, ?)`, portID, scan.ScanTime, string(status))
		if err != nil {
			tx.Rollback()
			return err
		}

		db.Logger.Debug("Inserted scan history", zap.Any("portID", portID), zap.Any("scanTime", scan.ScanTime), zap.Any("status", string(status)))

	}

	return tx.Commit()
}

func (db *DBClient) HostExists(ctx context.Context, host string) (bool, error) {
	res, err := db.DB.QueryContext(ctx, `SELECT ip FROM scan_results WHERE ip = ?`, host)
	if err != nil {
		return false, err
	}

	defer res.Close()

	if res.Next() {
		return true, nil
	}

	return false, nil
}

// QueryByHostsAndPorts
/* QueryByHostsAndPorts is a method accepts a map of IPs and their ports,
and returns a map of IPs where the key is the IP and the value is a
map where the key is the port and the value is a map where the key is
the scan time and the value is the status of the port at that time. */
func (db *DBClient) QueryByHostsAndPorts(ctx context.Context, ipAndPorts map[string][]int) (*HistoricalScanData, error) {
	var ipHistories []IPHistory

	db.Logger.Debug("ipAndPorts", zap.Any("ipAndPorts", ipAndPorts))
	// Iterate through the IPs and their respective ports
	for ip, ports := range ipAndPorts {
		placeholders := make([]string, len(ports))
		args := make([]interface{}, len(ports)+1)
		var portHistories []PortHistory

		args[0] = ip
		for i, port := range ports {
			placeholders[i] = "?"
			args[i+1] = port
		}

		db.Logger.Debug("placeholders", zap.Any("placeholders", placeholders), zap.Any("args", args))

		// Construct the query for this IP and ports
		query := fmt.Sprintf(`
			SELECT pr.port_number, pr.status, sr.scan_time
			FROM port_results AS pr
			JOIN scan_results AS sr ON pr.scan_id = sr.scan_id
			WHERE sr.ip = ? AND pr.port_number IN (%s)
		`, strings.Join(placeholders, ", "))

		// Execute the query
		rows, err := db.DB.QueryContext(ctx, query, args...)
		if err != nil {
			return nil, fmt.Errorf("error executing query: %w", err)
		}

		defer rows.Close()

		// Iterate through the rows, populating the result
		portHistoriesMap := make(map[int][]ScanTimeStatus)
		for rows.Next() {
			var portNumber int
			var status string
			var scanTimeStr string
			err := rows.Scan(&portNumber, &status, &scanTimeStr)
			if err != nil {
				return nil, fmt.Errorf("error scanning row: %w", err)
			}
			scanTime, err := time.Parse("2006-01-02 15:04:05", scanTimeStr)
			if err != nil {
				return nil, fmt.Errorf("error parsing scan time: %w", err)
			}

			db.Logger.Debug("portNumber", zap.Any("portNumber", portNumber), zap.Any("status", status), zap.Any("scanTime", scanTime))
			portHistoriesMap[portNumber] = append(portHistoriesMap[portNumber], ScanTimeStatus{Time: scanTime, Status: status})
		}

		// Convert the portHistoriesMap to the required slice structure
		for port, history := range portHistoriesMap {
			portHistories = append(portHistories, PortHistory{PortNumber: port, History: history})
		}

		// Add the results for this IP
		ipHistories = append(ipHistories, IPHistory{IP: ip, Port: portHistories})
	}

	db.Logger.Debug("result", zap.Any("result", ipHistories))
	result := &HistoricalScanData{Data: ipHistories}

	return result, nil
}

func (db *DBClient) UpsertScanResults(ctx context.Context, scan ScanResult) error {
	// Start a transaction
	tx, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	// Check if the scan result for the IP already exists
	exists, err := db.HostExists(ctx, scan.IP)
	if err != nil {
		tx.Rollback()
		return err
	}

	if exists {
		// Update existing scan result
		err = db.UpdateScanResults(ctx, scan)
		if err != nil {
			tx.Rollback()
			return err
		}
	} else {
		// Insert new scan result
		err = db.InsertScanResults(ctx, scan)
		if err != nil {
			tx.Rollback()
			return err
		}
	}

	// Commit the transaction
	err = tx.Commit()
	if err != nil {
		return err
	}

	return nil
}
