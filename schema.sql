DROP TABLE IF EXISTS Entries;

CREATE TABLE IF NOT EXISTS Entries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  masterKey TEXT NOT NULL,

  memberKey TEXT NOT NULL,
  memberMetadata TEXT NOT NULL,
  memberSignature TEXT NOT NULL,

  bodyData TEXT NOT NULL,
  bodyTimestamp INTEGER NOT NULL, 
  bodySignature TEXT NOT NULL
);
