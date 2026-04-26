CREATE DATABASE IF NOT EXISTS phishing_db;
USE phishing_db;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) UNIQUE,
    password_hash TEXT,
    email VARCHAR(100) UNIQUE,
    reset_token VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    url TEXT,
    result VARCHAR(20),
    score INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS support_requests (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    subject VARCHAR(255),
    requester_name VARCHAR(100),
    contact_email VARCHAR(100),
    message TEXT,
    status VARCHAR(50) DEFAULT 'Open',
    admin_response TEXT,
    resolved_at DATETIME NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
