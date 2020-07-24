CREATE DATABASE ctdownload ENCODING='UTF8';

\c ctdownload

CREATE TABLE downloaded_certs (
    MD5 uuid NOT NULL, -- use MD5 here because it fits into optimized UUID type
    TBS_NO_CT_MD5 uuid NOT NULL
);

--
-- -- Schema taken from crt.sh https://github.com/crtsh/certwatch_db/blob/master/sql/create_schema.sql
-- CREATE TABLE ct_log (
-- 	ID						integer,
-- 	OPERATOR				text,
-- 	URL						text,
-- 	NAME					text,
-- 	PUBLIC_KEY				bytea,
-- 	IS_ACTIVE				boolean,
-- 	LATEST_UPDATE			timestamp,
-- 	LATEST_STH_TIMESTAMP	timestamp,
-- 	MMD_IN_SECONDS			integer,
-- 	TREE_SIZE				integer,
-- 	BATCH_SIZE				integer,
-- 	CHUNK_SIZE				integer,
-- 	GOOGLE_UPTIME			text,
-- 	CHROME_VERSION_ADDED	integer,
-- 	CHROME_INCLUSION_STATUS	text,
-- 	CHROME_ISSUE_NUMBER		integer,
-- 	CHROME_FINAL_TREE_SIZE	integer,
-- 	CHROME_DISQUALIFIED_AT	timestamp,
-- 	APPLE_INCLUSION_STATUS	text,
-- 	APPLE_LAST_STATE_CHANGE	timestamp,
-- 	CONSTRAINT ctl_pk
-- 		PRIMARY KEY (ID),
-- 	CONSTRAINT ctl_url_unq
-- 		UNIQUE (URL)
-- );

GRANT ALL ON ALL TABLES IN SCHEMA public TO ctdownloader;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO ctdownloader;