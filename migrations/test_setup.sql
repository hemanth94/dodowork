CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    balance NUMERIC(15,2) NOT NULL DEFAULT 0.00
);

CREATE TYPE transaction_type AS ENUM ('DEPOSIT', 'WITHDRAWAL');

CREATE TABLE transactions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    amount NUMERIC(15,2) NOT NULL,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    transaction_type transaction_type NOT NULL
);