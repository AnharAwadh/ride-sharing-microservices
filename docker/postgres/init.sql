-- Create schemas for each microservice
CREATE SCHEMA IF NOT EXISTS gateway;
CREATE SCHEMA IF NOT EXISTS customer;
CREATE SCHEMA IF NOT EXISTS driver;

-- Grant permissions
GRANT ALL ON SCHEMA gateway TO postgres;
GRANT ALL ON SCHEMA customer TO postgres;
GRANT ALL ON SCHEMA driver TO postgres;
