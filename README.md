

# How to run:
## Prepare & start the backend Go application
Prepare the Database: Run the script located in the scripts directory to create the MySQL database.

```bash
cd backend/scripts
sh create-database.sh
```
Start the Servers: Run the script to start the MySQL server, GoLang server, and export required environment variables.

```bash
cd backend/scripts
sh start-database.sh
sh start-server.sh
```

## Start the frontend Sveltekit application
```bash
cd frontend
npm install
npm run dev -- --open
```


## Database Schema
The database schema consists of four tables that store information related to host scans, port results, port changes, and port scan history.

### `scan_results` Table
This table stores the result of each host scan.

scan_id: (Primary Key) A unique identifier for each scan.

host: The host or hostname scanned.

scan_time: The timestamp of when the scan was performed.

ip: The IP address of the host scanned.

### `port_results` Table

This table contains the result of port scans for each host.

port_id: (Primary Key) A unique identifier for each port result.

scan_id: (Foreign Key) References the scan_id in the scan_results table, linking the port result to a specific host scan.

port_number: The port number scanned.

status: The status of the port, e.g., open or closed.

scan_time: The timestamp of when the port scan was performed.

### `port_changes` Table
This table tracks changes to port statuses over time.

change_id: (Primary Key) A unique identifier for each change record.

port_id: (Foreign Key) References the port_id in the port_results table, linking the change to a specific port result.

change_type: The type of change, e.g., added or removed.

scan_time: The timestamp of when the change was detected.

### `port_scan_history` Table
This table maintains the history of port scans for analysis.

id: (Primary Key) A unique identifier for each scan history record.

port_id: (Foreign Key) References the port_id in the port_results table, linking the scan history to a specific port result.

scan_time: The timestamp of when the port scan was performed.

status: The status of the port at the time of the scan.