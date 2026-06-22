-- ADD DKIMStatus COLUMN TO mailbox
ALTER TABLE {{ tenant "mailbox" }} ADD COLUMN DKIMStatus TEXT NOT NULL DEFAULT '';
