--
-- PyDNS RuleEngine Database Backend Schema
--

-- keep track of data sources
CREATE TABLE IF NOT EXISTS Sources (
  SourceId    INT,
  Name        TEXT,
  Path        TEXT,
  LastUpdated DATETIME
);
CREATE INDEX IF NOT EXISTS Sources_1 ON Sources (SourceId);
CREATE INDEX IF NOT EXISTS Sources_2 ON Sources (Name);
CREATE INDEX IF NOT EXISTS Sources_3 ON Sources (Path);

-- regex patterns from a specific source
CREATE TABLE IF NOT EXISTS RegexPatterns (
  SourceId INT,
  Pattern  TEXT,
  Rule     INT
);
CREATE INDEX IF NOT EXISTS RegexPatterns_1 ON RegexPatterns (SourceId);

-- wildcard patterns from a specific source
CREATE TABLE IF NOT EXISTS WildcardPatterns (
  SourceId INT,
  Pattern  TEXT,
  Rule     INT
);
CREATE INDEX IF NOT EXISTS WildcardPatterns_1 ON WildcardPatterns (SourceId);

-- full domains associated with a specific source
CREATE TABLE IF NOT EXISTS Domains (
  SourceId INT,
  Domain   TEXT,
  Rule     INT
);
CREATE INDEX IF NOT EXISTS Domains_1 ON Domains (SourceId);
CREATE INDEX IF NOT EXISTS Domains_2 ON Domains (Domain);
