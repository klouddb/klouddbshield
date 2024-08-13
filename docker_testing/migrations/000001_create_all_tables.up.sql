-- Migration to create tables if not exists

-- Table: users
CREATE TABLE IF NOT EXISTS users (
    user_id SERIAL PRIMARY KEY,
    name VARCHAR(100),
    username VARCHAR(50) UNIQUE,
    user_email VARCHAR(100) UNIQUE,
    gender VARCHAR(20),
    nationality VARCHAR(50)
);

-- Table: contacts
CREATE TABLE IF NOT EXISTS contacts (
    contact_id SERIAL PRIMARY KEY,
    full_name VARCHAR(100),
    mobile_number VARCHAR(15),
    email_address VARCHAR(100),
    home_address VARCHAR(200),
    postal_code VARCHAR(20)
);

-- Table: employees
CREATE TABLE IF NOT EXISTS employees (
    employee_id SERIAL PRIMARY KEY,
    employee_name VARCHAR(100),
    ssn VARCHAR(11) UNIQUE,
    birth_date DATE,
    address VARCHAR(200),
    phone_number VARCHAR(20)
);

-- Table: orders
CREATE TABLE IF NOT EXISTS orders (
    order_id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(user_id),
    credit_card VARCHAR(19),
    po_box VARCHAR(20),
    order_date TIMESTAMP
);

-- Table: devices
CREATE TABLE IF NOT EXISTS devices (
    device_id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(user_id),
    ip_address VARCHAR(15),
    mac_address VARCHAR(17),
    location_info VARCHAR(200)
);

-- Table: sessions
CREATE TABLE IF NOT EXISTS sessions (
    session_id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(user_id),
    oauth_token VARCHAR(200),
    session_ip VARCHAR(15),
    login_time TIMESTAMP,
    logout_time TIMESTAMP
);

-- Table: logs
CREATE TABLE IF NOT EXISTS logs (
    log_id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(user_id),
    action_by VARCHAR(100),
    action_email VARCHAR(100),
    action_description VARCHAR(200),
    log_time TIMESTAMP
);

-- Table: customers
CREATE TABLE IF NOT EXISTS customers (
    customer_id SERIAL PRIMARY KEY,
    customer_name VARCHAR(100),
    phone VARCHAR(15),
    email VARCHAR(100),
    customer_address VARCHAR(200),
    zip_code VARCHAR(20),
    card_number VARCHAR(19)
);

-- Table: credentials
CREATE TABLE IF NOT EXISTS credentials (
    credential_id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(user_id),
    user_password VARCHAR(200),
    email VARCHAR(100),
    user_fullname VARCHAR(100)
);

-- Table: feedback
CREATE TABLE IF NOT EXISTS feedback (
    feedback_id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(user_id),
    user_email VARCHAR(100),
    feedback_text TEXT,
    feedback_date TIMESTAMP
);
