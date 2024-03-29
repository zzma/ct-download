\c ctdownload

CREATE UNIQUE INDEX downloaded_certs_sha256
    ON downloaded_certs (SHA256);

CREATE INDEX downloaded_certs_tbs_no_ct_SHA256
    ON downloaded_certs (TBS_NO_CT_SHA256);

GRANT ALL ON ALL TABLES IN SCHEMA public TO ctdownloader;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO ctdownloader;