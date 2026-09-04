#!/bin/sh
# Creates the greylisting database, user, and schema on first MariaDB start.
# Runs automatically from /docker-entrypoint-initdb.d/ — only on a fresh volume.
# Credentials come from the mariadb service environment (set in docker-compose.yml).
# Schema from greylisting-0.5 (Manuel Mausz) for qmail-spp MySQL greylisting plugin.

GREYLIST_DB="${GREYLIST_DB:-greylisting}"
GREYLIST_USER="${GREYLIST_USER:-greylisting}"
GREYLIST_PASS="${GREYLIST_PASS:-changeme_grey}"

mariadb -u root -p"${MARIADB_ROOT_PASSWORD}" <<SQL
CREATE DATABASE IF NOT EXISTS \`${GREYLIST_DB}\`;
CREATE USER IF NOT EXISTS '${GREYLIST_USER}'@'%' IDENTIFIED BY '${GREYLIST_PASS}';
GRANT ALL PRIVILEGES ON \`${GREYLIST_DB}\`.* TO '${GREYLIST_USER}'@'%';
USE \`${GREYLIST_DB}\`;

-- White/blacklist table: per-IP or per-domain overrides.
-- block_expires in past = whitelist (skip greylisting); in future = blacklist (hard reject).
CREATE TABLE IF NOT EXISTS greylisting_lists (
  id              int unsigned    NOT NULL AUTO_INCREMENT,
  ipaddr          varchar(43),
  ipaddr_start    varbinary(16),
  ipaddr_end      varbinary(16),
  ipaddr_prefixsize tinyint unsigned,
  rcpt_to         varchar(255)    DEFAULT NULL,
  block_expires   datetime        NOT NULL,
  record_expires  datetime        NOT NULL,
  create_time     timestamp       NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_update     timestamp       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  comment         varchar(255)    NOT NULL,
  PRIMARY KEY (id),
  KEY ipaddr_start (ipaddr_start),
  KEY ipaddr_end   (ipaddr_end),
  KEY rcpt_to      (rcpt_to(20))
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- Triplet state table: (relay_ip, mail_from, rcpt_to) → block/pass tracking.
CREATE TABLE IF NOT EXISTS greylisting_data (
  id             bigint unsigned  NOT NULL AUTO_INCREMENT,
  relay_ip       varbinary(16),
  mail_from      varchar(255)     DEFAULT NULL,
  rcpt_to        varchar(255)     DEFAULT NULL,
  block_expires  datetime         NOT NULL,
  record_expires datetime         NOT NULL,
  blocked_count  int unsigned     NOT NULL DEFAULT 0,
  passed_count   int unsigned     NOT NULL DEFAULT 0,
  aborted_count  int unsigned     NOT NULL DEFAULT 0,
  create_time    timestamp        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_update    timestamp        NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY relay_ip  (relay_ip),
  KEY mail_from (mail_from(20)),
  KEY rcpt_to   (rcpt_to(20))
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

FLUSH PRIVILEGES;
SQL
