<?php

declare(strict_types=1);

namespace Tob\Auth0\Contracts;

interface DatabaseInterface
{
    public function createTable(string $table);

    public function deleteRow(string $table, array $where, array $format): int|bool;

    public function getTableName(string $table): string;

    public function insertRow(string $table, array $data, array $formats): int|bool;

    public function selectRow(string $select, string $from, string $query, array $args = []): array|object|null;

    public function selectResults(string $select, string $from, string $query, array $args = []): array|object|null;

    public function upgradeTable(string $table): void;
}
