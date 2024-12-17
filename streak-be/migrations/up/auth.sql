-- Create a function to update the updated_at column
CREATE
OR REPLACE FUNCTION set_updated_at_column () RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = current_timestamp; 
    RETURN NEW; 
END;
$$ LANGUAGE plpgsql;

-- Create case-insensitive text column
CREATE EXTENSION IF NOT EXISTS CITEXT;

CREATE SCHEMA IF NOT EXISTS auth;

-- Roles table
CREATE TABLE IF NOT EXISTS auth.roles (role TEXT PRIMARY KEY);

-- USER - Regular user
-- ADMIN - Admin user
INSERT INTO
    auth.roles (role)
VALUES
    ('USER'),
    ('ADMIN');

-- Account statuses table
CREATE TABLE IF NOT EXISTS auth.account_statuses (account_status TEXT PRIMARY KEY);

-- PENDING - Pending account verification
-- ACTIVE - Active account
-- SUSPENDED - Disabled by admin
-- DELETED - Disabled by user
INSERT INTO
    auth.account_statuses (account_status)
VALUES
    ('PENDING'),
    ('ACTIVE'),
    ('SUSPENDED'),
    ('DELETED');

-- Genders table
CREATE TABLE IF NOT EXISTS auth.user_genders (gender TEXT PRIMARY KEY);

INSERT INTO
    auth.user_genders (gender)
VALUES
    ('MALE'),
    ('FEMALE'),
    ('OTHER');

-- Users table
CREATE TABLE IF NOT EXISTS auth.users (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    role TEXT NOT NULL REFERENCES auth.roles (role) ON DELETE RESTRICT,
    email CITEXT NOT NULL UNIQUE CHECK (length(email) <= 64),
    password_hash TEXT CHECK (length(password_hash) <= 1024),
    username TEXT CHECK (length(username) <= 64),
    image_url TEXT CHECK (length(image_url) <= 1024),
    gender CITEXT REFERENCES auth.user_genders (gender) ON DELETE RESTRICT,
    date_of_birth DATE CHECK (date_of_birth >= '1900-01-01'),
    account_status TEXT NOT NULL REFERENCES auth.account_statuses (account_status) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ DEFAULT current_timestamp NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT current_timestamp NOT NULL
);

CREATE TRIGGER set_users_updated_at BEFORE
UPDATE ON auth.users FOR EACH ROW
EXECUTE FUNCTION set_updated_at_column ();

-- Refresh tokens table
CREATE TABLE IF NOT EXISTS auth.refresh_tokens (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
    refresh_token TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT current_timestamp NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT current_timestamp NOT NULL
);

CREATE TRIGGER set_refresh_tokens_updated_at BEFORE
UPDATE ON auth.refresh_tokens FOR EACH ROW
EXECUTE FUNCTION set_updated_at_column ();

-- User preferences themes
CREATE TABLE IF NOT EXISTS auth.user_preference_themes (theme TEXT PRIMARY KEY);

INSERT INTO
    auth.user_preference_themes (theme)
VALUES
    ('LIGHT'),
    ('DARK'),
    ('SYSTEM');

-- User preferences table
CREATE TABLE IF NOT EXISTS auth.user_preferences (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
    theme TEXT NOT NULL REFERENCES auth.user_preference_themes (theme) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ DEFAULT current_timestamp NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT current_timestamp NOT NULL
);

CREATE TRIGGER set_user_preferences_updated_at BEFORE
UPDATE ON auth.user_preferences FOR EACH ROW
EXECUTE FUNCTION set_updated_at_column ();