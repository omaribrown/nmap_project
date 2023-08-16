# Nmap Project
## Description:
This project is a web application that allows users to scan a website for open ports. The application will display the results of the scan and the history of the scan results. 
# How to run (not functional):
This section is incomplete, and will not run by following these instructions.
## Prepare & start the backend Go application
Prepare the Database: Run this SQL query to create the MySQL database. The database name is nmap_project. The database user is `root` and the password is `Aventis2012`. The database is hosted on localhost:3306. The database is created with two tables: Hosts and ScanResults. The Hosts table stores the hostname and ip_address of the host. The ScanResults table stores the results of the port scan. The ScanResults table has a foreign key constraint on the Hosts table. 

```sql
create database nmap_project;

use nmap_project;

create table Hosts(
    host_id int primary key auto_increment,
    hostname varchar(255),
    ip_address varchar(255) not null unique
);

create table ScanResults(
    scan_id int primary key auto_increment,
    ip_address varchar(255) not null,
    port int not null,
    timestamp timestamp,
    status varchar(255),
    foreign key (ip_address) references Hosts(ip_address)
);
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

Examples:

`www.medium.com`

```json
{
    "host": {
        "ip_address": "162.159.153.4",
        "hostname": "www.medium.com"
    },
    "scan_results": [
        {
            "ip_address": "162.159.153.4",
            "timestamp": "2023-08-16T08:15:17-04:00",
            "port": 80,
            "status": "open"
        },
        {
            "ip_address": "162.159.153.4",
            "timestamp": "2023-08-16T08:15:17-04:00",
            "port": 443,
            "status": "open"
        }
    ],
    "port_history": [
        {
            "scan_id": "69",
            "ip_address": "162.159.153.4",
            "timestamp": "2023-08-16T12:11:55Z",
            "port": 80,
            "status": "open"
        },
        {
            "scan_id": "70",
            "ip_address": "162.159.153.4",
            "timestamp": "2023-08-16T12:11:55Z",
            "port": 443,
            "status": "open"
        }
    ]
}
```
