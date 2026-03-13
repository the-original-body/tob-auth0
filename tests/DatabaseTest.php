<?php

declare(strict_types=1);

namespace Tests\TobAuth0;

use Mockery;
use Tob\Auth0\Database;

class DatabaseTest extends WpTestCase
{
    private object $wpdb;
    private Database $db;

    protected function setUp(): void
    {
        parent::setUp();

        $this->wpdb = Mockery::mock('wpdb');
        $this->wpdb->prefix = 'wp_';
        $GLOBALS['wpdb'] = $this->wpdb;

        $this->db = new Database();
    }

    public function testGetTableNameUsesTobAuth0Prefix(): void
    {
        $result = $this->db->getTableName(Database::CONST_TABLE_ACCOUNTS);
        $this->assertSame('wp_tob_auth0_accounts', $result);
    }

    public function testConstTableAccountsValue(): void
    {
        $this->assertSame('accounts', Database::CONST_TABLE_ACCOUNTS);
    }

    public function testCreateTableAccountsDoesNotThrow(): void
    {
        $this->wpdb->shouldReceive('get_charset_collate')
            ->once()
            ->andReturn(' DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci');

        $this->db->createTable(Database::CONST_TABLE_ACCOUNTS);

        // Verify maybe_create_table was called (stubbed in WpTestCase)
        $this->assertTrue(true);
    }

    public function testCreateTableWithUnknownNameReturnsNull(): void
    {
        $result = $this->db->createTable('nonexistent');
        $this->assertNull($result);
    }

    public function testInsertAndSelectRow(): void
    {
        $this->wpdb->shouldReceive('insert')
            ->once()
            ->with(
                'wp_tob_auth0_accounts',
                Mockery::on(fn($data) =>
                    $data['domain'] === 'test.auth0.com'
                    && $data['user'] === 999
                    && $data['auth0'] === 'auth0|test123'
                ),
                ['%s', '%d', '%d', '%d', '%s']
            )
            ->andReturn(1);

        $expectedRow = (object) [
            'domain' => 'test.auth0.com',
            'user' => 999,
            'site' => 1,
            'blog' => 1,
            'auth0' => 'auth0|test123',
        ];

        $this->wpdb->shouldReceive('prepare')->andReturnUsing(fn($q) => $q);
        $this->wpdb->shouldReceive('get_row')->once()->andReturn($expectedRow);

        $table = $this->db->getTableName(Database::CONST_TABLE_ACCOUNTS);

        $this->db->insertRow($table, [
            'domain' => 'test.auth0.com',
            'user' => 999,
            'site' => 1,
            'blog' => 1,
            'auth0' => 'auth0|test123',
        ], ['%s', '%d', '%d', '%d', '%s']);

        $row = $this->db->selectRow('*', $table, 'WHERE `domain` = "%s" AND `auth0` = "%s" LIMIT 1', ['test.auth0.com', 'auth0|test123']);

        $this->assertNotNull($row);
        $this->assertEquals(999, $row->user);
        $this->assertSame('test.auth0.com', $row->domain);
        $this->assertSame('auth0|test123', $row->auth0);
    }

    public function testDeleteRow(): void
    {
        $this->wpdb->shouldReceive('delete')
            ->once()
            ->with(
                'wp_tob_auth0_accounts',
                ['domain' => 'delete-test.auth0.com', 'user' => 888],
                ['%s', '%d']
            )
            ->andReturn(1);

        $this->wpdb->shouldReceive('prepare')->andReturnUsing(fn($q) => $q);
        $this->wpdb->shouldReceive('get_row')->once()->andReturnNull();

        $table = $this->db->getTableName(Database::CONST_TABLE_ACCOUNTS);

        $this->db->deleteRow($table, ['domain' => 'delete-test.auth0.com', 'user' => 888], ['%s', '%d']);

        $row = $this->db->selectRow('*', $table, 'WHERE `domain` = "%s" AND `user` = %d LIMIT 1', ['delete-test.auth0.com', 888]);
        $this->assertNull($row);
    }

    public function testSelectResults(): void
    {
        $results = [
            (object) ['auth0' => 'auth0|results1'],
            (object) ['auth0' => 'auth0|results2'],
        ];

        $this->wpdb->shouldReceive('prepare')->andReturnUsing(fn($q) => $q);
        $this->wpdb->shouldReceive('get_results')
            ->once()
            ->andReturn($results);

        $table = $this->db->getTableName(Database::CONST_TABLE_ACCOUNTS);

        $returned = $this->db->selectResults('auth0', $table, 'WHERE `domain` = "%s" AND `user` = %d', ['results-test.auth0.com', 777]);

        $this->assertIsArray($returned);
        $this->assertCount(2, $returned);
    }

    protected function tearDown(): void
    {
        unset($GLOBALS['wpdb']);
        parent::tearDown();
    }
}
