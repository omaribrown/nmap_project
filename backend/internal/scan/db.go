package scan

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"go.uber.org/zap"
)

// IDBClient is an interface that defines the methods for interacting with the database.
type IDBClient interface {
	QueryPortHistory(ctx context.Context, ipAddress string, scans []*ScanResult) ([]*ScanResult, error)
	UpsertScanResults(ctx context.Context, host Host, scanResults []*ScanResult) error
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

// hostExists checks if an ip address exists in the database's Hosts table
func (db *DBClient) hostExists(ctx context.Context, ipAddress string) (bool, error) {
	res, err := db.DB.QueryContext(ctx, `SELECT ip_address FROM Hosts WHERE ip_address = ?`, ipAddress)
	if err != nil {
		return false, err
	}

	defer res.Close()

	if res.Next() {
		return true, nil
	}

	return false, nil
}

// QueryPortHistory queries the database for the port history of a given ports for a given IP address.
func (db *DBClient) QueryPortHistory(ctx context.Context, ipAddress string, scans []*ScanResult) ([]*ScanResult, error) {
	// Start a transaction
	tx, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}

	// Query the database for all the scan results for the given IP address as the ip_address column of the scan_results table
	rows, err := tx.QueryContext(ctx, `SELECT * FROM ScanResults WHERE ip_address = ?`, ipAddress)
	if err != nil {
		tx.Rollback()
		return nil, err
	}

	// Iterate through the rows and find records where the port number is in the list of ports
	var matchedPorts []*ScanResult
	for rows.Next() {
		var scanResult ScanResult
		var scanTimeStr string
		err := rows.Scan(&scanResult.ScanID, &scanResult.IPAddress, &scanResult.Port, &scanTimeStr, &scanResult.Status)
		if err != nil {
			tx.Rollback()
			return nil, err
		}

		// Iterate through the list of ports and find the matching port for the row
		for _, scan := range scans {
			if scanResult.Port == scan.Port {
				scanResult.Timestamp, err = time.Parse("2006-01-02 15:04:05", scanTimeStr)
				if err != nil {
					tx.Rollback()
					return nil, err
				}

				matchedPorts = append(matchedPorts, &scanResult)
			}
		}
	}

	// Commit the transaction
	err = tx.Commit()
	if err != nil {
		return nil, err
	}

	return matchedPorts, nil
}

// UpsertScanResults inserts scan results in the database.
func (db *DBClient) UpsertScanResults(ctx context.Context, host Host, scanResults []*ScanResult) error {
	tx, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	// Check if the host exists in the database
	hostExists, err := db.hostExists(ctx, host.IPAddress)
	if err != nil {
		return err
	}

	// If the host doesn't exist in the database, we need to insert it
	if !hostExists {
		queryString := `INSERT INTO Hosts (ip_address, hostname) VALUES (?, ?)`
		_, err = tx.ExecContext(ctx, queryString, host.IPAddress, host.Hostname)
		if err != nil {
			tx.Rollback()
			return err
		}
	}

	// Insert the scan results
	for _, scan := range scanResults {
		queryString := `INSERT INTO ScanResults (ip_address, port, timestamp, status) VALUES (?, ?, ?, ?)`
		_, err = tx.ExecContext(ctx, queryString, host.IPAddress, scan.Port, scan.Timestamp, scan.Status)
		if err != nil {
			tx.Rollback()
			return err
		}
	}

	// Commit the transaction
	return tx.Commit()
}
