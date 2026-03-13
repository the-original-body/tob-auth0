<?php

declare(strict_types=1);

namespace Tob\Auth0;

use Tob\Auth0\Contracts\DatabaseInterface;
use Throwable;

final class Database implements DatabaseInterface
{
    public const string CONST_TABLE_ACCOUNTS = 'accounts';

    public function createTable(string $table)
    {
        if (self::CONST_TABLE_ACCOUNTS === $table) {
            return $this->createTableAccounts();
        }
    }

    public function deleteRow(string $table, array $where, array $format): int|bool
    {
        return $this->getWpdb()->delete($table, $where, $format);
    }

    public function getTableName(string $table): string
    {
        return $this->getWpdb()->prefix . 'tob_auth0_' . $table;
    }

    public function insertRow(string $table, array $data, array $formats): int|bool
    {
        try {
            return $this->getWpdb()->insert($table, $data, $formats);
        } catch (Throwable) {
            return false;
        }
    }

    public function selectRow(string $select, string $from, string $query, array $args = []): array|object|null
    {
        $query = $this->getWpdb()->prepare($query, ...$args);

        return $this->getWpdb()->get_row(sprintf('SELECT %s FROM %s ', $select, $from) . $query);
    }

    public function selectResults(string $select, string $from, string $query, array $args = []): array|object|null
    {
        $query = $this->getWpdb()->prepare($query, ...$args);

        return $this->getWpdb()->get_results(sprintf('SELECT %s FROM %s ', $select, $from) . $query);
    }

    public function upgradeTable(string $table): void
    {
        if (self::CONST_TABLE_ACCOUNTS === $table) {
            $this->upgradeTableAccounts();
        }
    }

    private function createTableAccounts(): bool
    {
        $charset = $this->getWpdb()->get_charset_collate();
        $table = $this->getTableName(self::CONST_TABLE_ACCOUNTS);

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';

        return maybe_create_table(
            $table,
            sprintf('CREATE TABLE %s (
            id BIGINT NOT NULL AUTO_INCREMENT,
            domain VARCHAR(255) NOT NULL,
            site TINYINT NOT NULL,
            blog BIGINT NOT NULL,
            user BIGINT NOT NULL,
            auth0 VARCHAR(255) NOT NULL,
            PRIMARY KEY (id),
            UNIQUE KEY uq_domain_auth0 (domain, auth0),
            KEY idx_domain (domain)
        )' . $charset . ';', $table),
        );
    }

    private function upgradeTableAccounts(): void
    {
        $wpdb = $this->getWpdb();
        $table = $this->getTableName(self::CONST_TABLE_ACCOUNTS);

        // Migrate auth0 column from TEXT to VARCHAR(255)
        $column = $wpdb->get_row("SHOW COLUMNS FROM {$table} WHERE Field = 'auth0'");
        if ($column && str_starts_with(strtolower($column->Type), 'text')) {
            $wpdb->query("ALTER TABLE {$table} MODIFY `auth0` VARCHAR(255) NOT NULL");
        }

        // Add unique constraint on domain + auth0
        $indexes = $wpdb->get_results("SHOW INDEX FROM {$table} WHERE Key_name = 'uq_domain_auth0'");
        if (empty($indexes)) {
            // Remove duplicates before adding unique constraint (keep lowest id)
            $wpdb->query("DELETE t1 FROM {$table} t1 INNER JOIN {$table} t2 WHERE t1.id > t2.id AND t1.domain = t2.domain AND t1.auth0 = t2.auth0");
            $wpdb->query("ALTER TABLE {$table} ADD UNIQUE KEY uq_domain_auth0 (domain, auth0)");
        }
    }

    private function getWpdb(): object
    {
        global $wpdb;

        return $wpdb;
    }
}
