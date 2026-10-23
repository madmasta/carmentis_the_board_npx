-- The Board schema (MySQL 8 / MariaDB 10.6+)
--
-- Node port: every table, column, type, enum, foreign key and check below is
-- copied verbatim from the PHP reference target's schema.sql. The only addition
-- is the `sessions` table at the end (docs/07-port-deviations.md section 2).
-- docs/parity/schema-inventory.md is generated from the PHP file and is checked
-- against this file by `npm run verify:parity`.

CREATE TABLE IF NOT EXISTS users (
    id            INT UNSIGNED     NOT NULL AUTO_INCREMENT,
    username      VARCHAR(50)      NOT NULL,
    email         VARCHAR(255)     NOT NULL,
    password_hash VARCHAR(255)     NOT NULL,
    role          ENUM('user','admin') NOT NULL DEFAULT 'user',
    is_banned     TINYINT(1)       NOT NULL DEFAULT 0,
    ban_reason    VARCHAR(255)     NULL,
    avatar_path   VARCHAR(255)     NULL,
    mfa_enabled   TINYINT(1)       NOT NULL DEFAULT 0,
    created_at    TIMESTAMP        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    TIMESTAMP        NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_users_username (username),
    UNIQUE KEY uq_users_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS boards (
    id             INT UNSIGNED  NOT NULL AUTO_INCREMENT,
    name           VARCHAR(100)  NOT NULL,
    description    VARCHAR(500)  NOT NULL DEFAULT '',
    default_access TINYINT(1)    NOT NULL DEFAULT 0 COMMENT '1 = every active user has access',
    created_by     INT UNSIGNED  NULL,
    created_at     TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at     TIMESTAMP     NULL DEFAULT NULL,
    deleted_by     INT UNSIGNED  NULL,
    PRIMARY KEY (id),
    CONSTRAINT fk_boards_creator FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT fk_boards_deleter FOREIGN KEY (deleted_by) REFERENCES users (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS board_access (
    board_id   INT UNSIGNED NOT NULL,
    user_id    INT UNSIGNED NOT NULL,
    granted_by INT UNSIGNED NULL,
    granted_at TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (board_id, user_id),
    CONSTRAINT fk_ba_board FOREIGN KEY (board_id) REFERENCES boards (id) ON DELETE CASCADE,
    CONSTRAINT fk_ba_user  FOREIGN KEY (user_id)  REFERENCES users (id)  ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS posts (
    id         INT UNSIGNED NOT NULL AUTO_INCREMENT,
    board_id   INT UNSIGNED NOT NULL,
    parent_id  INT UNSIGNED NULL COMMENT 'NULL = top level thread, otherwise reply inside that thread',
    author_id  INT UNSIGNED NOT NULL,
    title      VARCHAR(200) NULL COMMENT 'only for top level threads',
    body       MEDIUMTEXT   NOT NULL,
    created_at TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    edited_at  TIMESTAMP     NULL,
    deleted_at TIMESTAMP     NULL,
    deleted_by INT UNSIGNED  NULL,
    PRIMARY KEY (id),
    KEY idx_posts_board (board_id, parent_id),
    KEY idx_posts_thread (parent_id),
    KEY idx_posts_author (author_id),
    KEY idx_posts_deleted (deleted_at),
    CONSTRAINT fk_posts_board  FOREIGN KEY (board_id)  REFERENCES boards (id) ON DELETE CASCADE,
    CONSTRAINT fk_posts_parent FOREIGN KEY (parent_id) REFERENCES posts (id) ON DELETE CASCADE,
    CONSTRAINT fk_posts_author FOREIGN KEY (author_id) REFERENCES users (id),
    CONSTRAINT fk_posts_deleter FOREIGN KEY (deleted_by) REFERENCES users (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS votes (
    post_id    INT UNSIGNED NOT NULL,
    user_id    INT UNSIGNED NOT NULL,
    value      TINYINT      NOT NULL COMMENT '1 = up, -1 = down',
    created_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (post_id, user_id),
    CONSTRAINT chk_votes_value CHECK (value IN (1, -1)),
    CONSTRAINT fk_votes_post FOREIGN KEY (post_id) REFERENCES posts (id) ON DELETE CASCADE,
    CONSTRAINT fk_votes_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS login_attempts (
    id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    email        VARCHAR(255)    NOT NULL,
    ip           VARCHAR(45)     NOT NULL,
    success      TINYINT(1)      NOT NULL DEFAULT 0,
    attempted_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_attempts_email (email, attempted_at),
    KEY idx_attempts_ip (ip, attempted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS mfa_codes (
    id         INT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id    INT UNSIGNED NOT NULL,
    code_hash  VARCHAR(255) NOT NULL,
    expires_at DATETIME     NOT NULL,
    attempts   INT UNSIGNED NOT NULL DEFAULT 0,
    used_at    DATETIME     NULL,
    created_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_mfa_user (user_id, used_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---- Node delta: database-backed sessions (docs/07 section 2) --------------
-- Replaces PHP's native file-backed sessions so session behaviour is observable
-- and attackable: `session_management`, `sqli` and `idor` all need a session
-- substrate in the database. `data` holds the session payload as JSON
-- (auth_user_id, mfa_pending_user_id, csrf_token, flash, intended_path,
-- mfa_last_sent, auth_created_at) — never an attacker-supplied blob.

CREATE TABLE IF NOT EXISTS sessions (
    id         CHAR(64)     NOT NULL,
    user_id    INT UNSIGNED NULL,
    data       JSON         NOT NULL,
    created_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP    NOT NULL,
    PRIMARY KEY (id),
    KEY idx_sessions_user (user_id),
    KEY idx_sessions_expiry (expires_at),
    CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
