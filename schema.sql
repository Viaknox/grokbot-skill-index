-- Empty skill library. Search does not write here.
-- Only a skill the user adds is inserted. Marketplace links stay search-only.

CREATE TABLE listings (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  purpose TEXT NOT NULL,
  keywords TEXT,
  do_not_use_when TEXT,
  success_check TEXT,
  repo TEXT,
  added_at TEXT NOT NULL
);

CREATE TABLE locations (
  id INTEGER PRIMARY KEY,
  listing_id INTEGER NOT NULL REFERENCES listings(id),
  store TEXT,
  url TEXT NOT NULL,
  license TEXT,
  last_checked TEXT
);

CREATE TABLE search_sources (
  id INTEGER PRIMARY KEY,
  name TEXT,
  url TEXT NOT NULL UNIQUE,
  added_at TEXT NOT NULL
);
