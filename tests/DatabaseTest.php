<?php

declare(strict_types=1);

namespace Tests\TobAuth0;

use PHPUnit\Framework\TestCase;
use Tob\Auth0\Database;

class DatabaseTest extends TestCase
{
    public function testGetTableNameUsesTobAuth0Prefix(): void
    {
        global $wpdb;
        $db = new Database();

        $result = $db->getTableName(Database::CONST_TABLE_ACCOUNTS);
        $this->assertSame($wpdb->prefix . 'tob_auth0_accounts', $result);
    }

    public function testConstTableAccountsValue(): void
    {
        $this->assertSame('accounts', Database::CONST_TABLE_ACCOUNTS);
    }

    public function testCreateTableAccountsDoesNotThrow(): void
    {
        $db = new Database();

        // Should not throw — creates table if not exists
        $db->createTable(Database::CONST_TABLE_ACCOUNTS);

        // Verify table exists
        global $wpdb;
        $tableName = $wpdb->prefix . 'tob_auth0_accounts';
        $exists = $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $tableName));
        $this->assertSame($tableName, $exists);
    }

    public function testCreateTableWithUnknownNameReturnsNull(): void
    {
        $db = new Database();
        $result = $db->createTable('nonexistent');
        $this->assertNull($result);
    }

    public function testInsertAndSelectRow(): void
    {
        $db = new Database();
        $db->createTable(Database::CONST_TABLE_ACCOUNTS);
        $table = $db->getTableName(Database::CONST_TABLE_ACCOUNTS);

        $db->insertRow($table, [
            'domain' => 'test.auth0.com',
            'user' => 999,
            'site' => 1,
            'blog' => 1,
            'auth0' => 'auth0|test123',
        ], ['%s', '%d', '%d', '%d', '%s']);

        $row = $db->selectRow('*', $table, 'WHERE `domain` = "%s" AND `auth0` = "%s" LIMIT 1', ['test.auth0.com', 'auth0|test123']);

        $this->assertNotNull($row);
        $this->assertEquals(999, $row->user);
        $this->assertSame('test.auth0.com', $row->domain);
        $this->assertSame('auth0|test123', $row->auth0);
    }

    public function testDeleteRow(): void
    {
        $db = new Database();
        $db->createTable(Database::CONST_TABLE_ACCOUNTS);
        $table = $db->getTableName(Database::CONST_TABLE_ACCOUNTS);

        $db->insertRow($table, [
            'domain' => 'delete-test.auth0.com',
            'user' => 888,
            'site' => 1,
            'blog' => 1,
            'auth0' => 'auth0|delete_me',
        ], ['%s', '%d', '%d', '%d', '%s']);

        $db->deleteRow($table, ['domain' => 'delete-test.auth0.com', 'user' => 888], ['%s', '%d']);

        $row = $db->selectRow('*', $table, 'WHERE `domain` = "%s" AND `user` = %d LIMIT 1', ['delete-test.auth0.com', 888]);
        $this->assertNull($row);
    }

    public function testSelectResults(): void
    {
        $db = new Database();
        $db->createTable(Database::CONST_TABLE_ACCOUNTS);
        $table = $db->getTableName(Database::CONST_TABLE_ACCOUNTS);

        $db->insertRow($table, [
            'domain' => 'results-test.auth0.com',
            'user' => 777,
            'site' => 1,
            'blog' => 1,
            'auth0' => 'auth0|results1',
        ], ['%s', '%d', '%d', '%d', '%s']);

        $db->insertRow($table, [
            'domain' => 'results-test.auth0.com',
            'user' => 777,
            'site' => 1,
            'blog' => 1,
            'auth0' => 'auth0|results2',
        ], ['%s', '%d', '%d', '%d', '%s']);

        $results = $db->selectResults('auth0', $table, 'WHERE `domain` = "%s" AND `user` = %d', ['results-test.auth0.com', 777]);

        $this->assertIsArray($results);
        $this->assertCount(2, $results);
    }

    protected function tearDown(): void
    {
        global $wpdb;
        $table = $wpdb->prefix . 'tob_auth0_accounts';
        $wpdb->query("DELETE FROM {$table} WHERE domain LIKE '%test%'");
    }
}
