m#!/bin/bash
# Database credentials
DB_NAME="nmap_scans"
DB_USER="default_user"

# Create the database
mysql -u$DB_USER -e "CREATE DATABASE $DB_NAME;"

# Create the user
mysql -u$DB_USER -e "CREATE USER '$DB_USER'@'localhost';"

# Grant privileges to the user
mysql -u$DB_USER -e "GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost';"

# Flush privileges
mysql -u$DB_USER -e "FLUSH PRIVILEGES;"

# Create the tables
mysql -u$DB_USER $DB_NAME <<EOF
CREATE TABLE scan_results (
  scan_id int NOT NULL AUTO_INCREMENT,
  host varchar(255) DEFAULT NULL,
  scan_time timestamp NOT NULL,
  ip varchar(255) NOT NULL,
  PRIMARY KEY (scan_id)
);

CREATE TABLE port_results (
  port_id int NOT NULL AUTO_INCREMENT,
  scan_id int NOT NULL,
  port_number int NOT NULL,
  status varchar(50) NOT NULL,
  scan_time timestamp NOT NULL,
  PRIMARY KEY (port_id),
  KEY port_results (scan_id),
  CONSTRAINT port_results FOREIGN KEY (scan_id) REFERENCES scan_results (scan_id)
);

CREATE TABLE port_changes (
  change_id int NOT NULL AUTO_INCREMENT,
  port_id int NOT NULL,
  change_type varchar(50) NOT NULL,
  scan_time datetime DEFAULT NULL,
  PRIMARY KEY (change_id),
  KEY port_changes (port_id),
  CONSTRAINT port_changes FOREIGN KEY (port_id) REFERENCES port_results (port_id)
);

CREATE TABLE port_scan_history (
  id int NOT NULL AUTO_INCREMENT,
  port_id int NOT NULL,
  scan_time timestamp NOT NULL,
  status varchar(255) NOT NULL,
  PRIMARY KEY (id),
  KEY port_id (port_id),
  CONSTRAINT port_scan_history_ibfk_1 FOREIGN KEY (port_id) REFERENCES port_results (port_id)
);
EOF

echo "Database $DB_NAME created with user $DB_USER. Tables have been created."
