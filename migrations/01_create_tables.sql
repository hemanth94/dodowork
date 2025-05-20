-- Create ENUM type for transaction_type
CREATE TYPE transaction_type AS ENUM ('DEPOSIT', 'WITHDRAWAL');

-- Create users table with balance column
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    balance NUMERIC(15, 2) NOT NULL DEFAULT 0.00,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create transactions table with transaction_type ENUM
CREATE TABLE transactions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    amount DECIMAL(15, 2) NOT NULL,
    description TEXT,
    transaction_type transaction_type NOT NULL DEFAULT 'DEPOSIT',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
