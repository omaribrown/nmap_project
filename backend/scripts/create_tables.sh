CREATE TABLE `scan_results` (
  `scan_id` int NOT NULL AUTO_INCREMENT,
  `host` varchar(255) DEFAULT NULL,
  `scan_time` timestamp NOT NULL,
  `ip` varchar(255) NOT NULL,
  PRIMARY KEY (`scan_id`)
) ENGINE=InnoDB AUTO_INCREMENT=19 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

  CREATE TABLE `port_changes` (
    `change_id` int NOT NULL AUTO_INCREMENT,
    `port_id` int NOT NULL,
    `change_type` varchar(50) NOT NULL,
    `scan_time` datetime DEFAULT NULL,
    PRIMARY KEY (`change_id`),
    KEY `port_id` (`port_id`),
    CONSTRAINT `port_changes_ibfk_1` FOREIGN KEY (`port_id`) REFERENCES `port_results` (`port_id`)
  ) ENGINE=InnoDB AUTO_INCREMENT=37 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

    CREATE TABLE `port_results` (
      `port_id` int NOT NULL AUTO_INCREMENT,
      `scan_id` int NOT NULL,
      `port_number` int NOT NULL,
      `status` varchar(50) NOT NULL,
      PRIMARY KEY (`port_id`),
      KEY `scan_id` (`scan_id`),
      CONSTRAINT `port_results_ibfk_1` FOREIGN KEY (`scan_id`) REFERENCES `scan_results` (`scan_id`)
    ) ENGINE=InnoDB AUTO_INCREMENT=48 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci