CREATE DATABASE IF NOT EXISTS scanmypills;
USE scanmypills;

CREATE TABLE IF NOT EXISTS users (
    id INT(11) AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    reset_otp VARCHAR(6) DEFAULT NULL,
    otp_expires_at DATETIME DEFAULT NULL,
    otp_verified TINYINT(1) DEFAULT 0,
    otp_created_at DATETIME DEFAULT NULL,
    phone VARCHAR(15) DEFAULT NULL,
    profile_photo VARCHAR(255) DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS medicines (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    name VARCHAR(255) NOT NULL,
    manufacturer VARCHAR(255),
    expiry_date DATE,
    batch_number VARCHAR(100),
    mrp DECIMAL(10,2),
    dosage VARCHAR(255),
    category VARCHAR(255),
    quantity INT DEFAULT 0,
    front_image VARCHAR(255),
    back_image VARCHAR(255),
    main_image VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS reminders (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    medicine_id INT,
    reminder_time VARCHAR(255) NOT NULL,
    dosage VARCHAR(100),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(medicine_id) REFERENCES medicines(id) ON DELETE CASCADE
);
