CREATE EXTENSION IF NOT EXISTS dblink;

DO $$
BEGIN
    -- Проверяем, существует ли база данных с именем 'car_dealer'
    IF NOT EXISTS (
        SELECT FROM pg_database WHERE datname = 'car_dealer'
    ) THEN
        PERFORM dblink_exec('dbname=postgres', 'CREATE DATABASE car_dealer');
    ELSE
        RAISE NOTICE 'Database "car_dealer" already exists.';
    END IF;
END $$;

\c car_dealer;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT FROM pg_catalog.pg_roles
        WHERE rolname = 'car_dealer_user'
    ) THEN
        CREATE ROLE car_dealer_user WITH LOGIN PASSWORD '!322@VTB';
        ALTER ROLE car_dealer_user WITH SUPERUSER CREATEROLE CREATEDB;
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS users (
    id_users SERIAL PRIMARY KEY,
    surname VARCHAR(25) NOT NULL,
    name VARCHAR(20) NOT NULL,
    middle_name  VARCHAR(20),
    phone_number VARCHAR(11) UNIQUE NOT NULL,
    email VARCHAR(50) UNIQUE NOT NULL,
    hashed_password VARCHAR(100) NOT NULL,
    time_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP 
);

CREATE TABLE IF NOT EXISTS cars (
    id_car SERIAL PRIMARY KEY,
    brand VARCHAR(20) NOT NULL,
    model VARCHAR(25) NOT NULL,
    year INT NOT NULL,
    engine_volume DECIMAL(3, 1) NOT NULL,
    power INT NOT NULL,
    transmission VARCHAR(20) NOT NULL,
    color VARCHAR(20) NOT NULL,
    price INT NOT NULL,
    id_seller INT NOT NULL,
    CONSTRAINT fk_seller FOREIGN KEY (id_seller) REFERENCES users(id_users)
);
