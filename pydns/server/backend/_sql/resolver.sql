--
-- Sqlite3 Resolver Cache Schema
--

-- translate domain into simpler domain-id
CREATE TABLE IF NOT EXISTS Domains (
  DomainId INT,
  Domain   TEXT
);
CREATE INDEX IF NOT EXISTS Domains_1 ON Domains (Domain);

-- store record values for the specified type
CREATE TABLE IF NOT EXISTS Records (
  DomainId   INT,
  RType      TEXT,
  Content    TEXT,
  Expiration DATETIME
);
CREATE INDEX IF NOT EXISTS Records_1 ON Records (DomainID, RType);
CREATE INDEX IF NOT EXISTS Records_2 ON Records (Expiration);
