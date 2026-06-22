-- CREATE FTS5 full-text search index for better Chinese search performance
CREATE VIRTUAL TABLE IF NOT EXISTS {{ tenant "mailbox_fts" }} USING fts5(
    SearchText,
    content='{{ tenant "mailbox" }}',
    content_rowid='Sort',
    tokenize='unicode61'
);

-- Trigger to keep FTS index in sync when inserting
CREATE TRIGGER IF NOT EXISTS {{ tenant "mailbox_ai" }} AFTER INSERT ON {{ tenant "mailbox" }} BEGIN
    INSERT INTO {{ tenant "mailbox_fts" }}(rowid, SearchText) VALUES (new.Sort, new.SearchText);
END;

-- Trigger to keep FTS index in sync when deleting
CREATE TRIGGER IF NOT EXISTS {{ tenant "mailbox_ad" }} AFTER DELETE ON {{ tenant "mailbox" }} BEGIN
    INSERT INTO {{ tenant "mailbox_fts" }}({{ tenant "mailbox_fts" }}, rowid, SearchText) VALUES('delete', old.Sort, old.SearchText);
END;
