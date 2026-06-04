--
-- Sqlite3 Stat Storage Schema
--

-- Track global stat counts per date
CREATE TABLE IF NOT EXISTS Stats (
  Date      DATETIME,
  Authority INT,
  Blocked   INT,
  Questions INT
);
CREATE INDEX IF NOT EXISTS Stats_1 ON Stats (Date);

-- Track questions per record-type per date
CREATE TABLE IF NOT EXISTS Questions (
  Date  DATETIME,
  RType TEXT,
  Count INT
);
CREATE INDEX IF NOT EXISTS Questions_1 ON Questions (Date, RType);

-- Track blocked questions per record-type per date
CREATE TABLE IF NOT EXISTS Blocked (
  Date  DATETIME,
  RType TEXT,
  Count INT
);
CREATE INDEX IF NOT EXISTS Blocked_1 ON Blocked (Date, RType);

-- Track questions answered from particular sources
CREATE TABLE IF NOT EXISTS Sources (
  Date   DATETIME,
  Source TEXT,
  Count  INT
);
CREATE INDEX IF NOT EXISTS Sources_1 ON Sources (Date, Source);

