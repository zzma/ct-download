CREATE DATABASE ctdownload ENCODING='UTF8';

\c ctdownload

CREATE TABLE downloaded_certs (
    SHA256 bytea NOT NULL,
    TBS_NO_CT_SHA256 bytea NOT NULL
);

GRANT ALL ON ALL TABLES IN SCHEMA public TO ctdownloader;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO ctdownloader;

