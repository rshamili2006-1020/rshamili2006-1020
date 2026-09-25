-- =============================================================
-- PhishGuard - Database Schema
-- =============================================================
-- Creates the `phishguard` database plus two tables (users, reports)
-- with appropriate indexes and a foreign-key relationship.
--
-- Compatible with MySQL 5.7+ / MariaDB 10.3+ (XAMPP).
-- Run inside phpMyAdmin or the MySQL CLI:
--     mysql -u root -p < database.sql
-- =============================================================

CREATE DATABASE IF NOT EXISTS phishguard
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE phishguard;

-- -------------------------------------------------------------
-- Table: users
-- -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    username      VARCHAR(20)  NOT NULL UNIQUE,
    email         VARCHAR(120) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_users_username (username),
    INDEX idx_users_email    (email)
) ENGINE = InnoDB;

-- -------------------------------------------------------------
-- Table: reports
-- -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS reports (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    user_id      INT           NOT NULL,
    url          VARCHAR(2048) NOT NULL,
    threat_level ENUM('Low','Medium','High','Critical')
                               NOT NULL DEFAULT 'Medium',
    status       ENUM('Open','Investigating','Resolved','False Positive')
                               NOT NULL DEFAULT 'Open',
    notes        TEXT,
    created_at   TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP
                                          ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_reports_user
        FOREIGN KEY (user_id) REFERENCES users (id)
        ON DELETE CASCADE ON UPDATE CASCADE,
    INDEX idx_reports_user_id      (user_id),
    INDEX idx_reports_threat_level (threat_level),
    INDEX idx_reports_status       (status),
    INDEX idx_reports_created_at   (created_at)
) ENGINE = InnoDB;
