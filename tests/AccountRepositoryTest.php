<?php

declare(strict_types=1);

namespace Tests\TobAuth0;

use Auth0\SDK\Configuration\SdkConfiguration;
use PHPUnit\Framework\TestCase;
use Tob\Auth0\AccountRepository;
use Tob\Auth0\Contracts\DatabaseInterface;
use Tob\Auth0\Contracts\SdkInterface;
use Tob\Auth0\Plugin;

class AccountRepositoryTest extends TestCase
{
    private DatabaseInterface $dbMock;
    private Plugin $plugin;
    private AccountRepository $repo;

    protected function setUp(): void
    {
        $sdkMock = $this->createMock(SdkInterface::class);
        $this->dbMock = $this->createMock(DatabaseInterface::class);

        $config = new SdkConfiguration(
            strategy: SdkConfiguration::STRATEGY_NONE,
            domain: 'test.eu.auth0.com',
            clientId: 'test_id',
            clientSecret: 'test_secret',
            cookieSecret: 'cookie_secret',
        );

        $this->plugin = new Plugin($sdkMock, $config);
        $this->repo = new AccountRepository($this->plugin, $this->dbMock);
    }

    public function testUpdateEmailReturnsSameUserWhenUnchanged(): void
    {
        $user = new \WP_User();
        $user->user_email = 'same@example.com';

        $result = $this->repo->updateEmail($user, 'same@example.com');

        $this->assertSame($user, $result);
    }

    public function testFindByConnectionReturnsNullWhenNotFound(): void
    {
        $this->dbMock->method('getTableName')->willReturn('wp_tob_auth0_accounts');
        $this->dbMock->expects($this->once())
            ->method('selectRow')
            ->willReturn(null);

        $result = $this->repo->findByConnection('auth0|nonexistent');

        $this->assertNull($result);
    }

    public function testCreateConnectionInsertsRow(): void
    {
        $user = new \WP_User();
        $user->ID = 42;

        $this->dbMock->method('getTableName')->willReturn('wp_tob_auth0_accounts');
        $this->dbMock->expects($this->once())
            ->method('selectRow')
            ->willReturn(null);
        $this->dbMock->expects($this->once())
            ->method('insertRow')
            ->willReturn(true);

        $this->repo->createConnection($user, 'auth0|test_sub');
    }

    public function testCreateConnectionSkipsWhenAlreadyExists(): void
    {
        $user = new \WP_User();
        $user->ID = 42;

        $this->dbMock->method('getTableName')->willReturn('wp_tob_auth0_accounts');
        $this->dbMock->expects($this->once())
            ->method('selectRow')
            ->willReturn((object) ['id' => 1]);
        $this->dbMock->expects($this->never())
            ->method('insertRow');

        $this->repo->createConnection($user, 'auth0|existing_sub');
    }

    public function testDeleteConnectionsReturnsNullWhenNone(): void
    {
        $this->dbMock->method('getTableName')->willReturn('wp_tob_auth0_accounts');
        $this->dbMock->expects($this->once())
            ->method('selectResults')
            ->willReturn(null);
        $this->dbMock->expects($this->never())
            ->method('deleteRow');

        $result = $this->repo->deleteConnections(999);

        $this->assertNull($result);
    }

    public function testDeleteConnectionsDeletesAndReturnsConnections(): void
    {
        $connections = [(object) ['auth0' => 'auth0|sub1']];

        $this->dbMock->method('getTableName')->willReturn('wp_tob_auth0_accounts');
        $this->dbMock->expects($this->once())
            ->method('selectResults')
            ->willReturn($connections);
        $this->dbMock->expects($this->once())
            ->method('deleteRow')
            ->willReturn(1);

        $result = $this->repo->deleteConnections(42);

        $this->assertSame($connections, $result);
    }

    public function testResolveIdentityReturnsNullWhenNoSubAndNotVerified(): void
    {
        $result = $this->repo->resolveIdentity(null, null, null);

        $this->assertNull($result);
    }

    public function testResolveIdentityReturnsNullForUnverifiedEmail(): void
    {
        $this->dbMock->method('getTableName')->willReturn('wp_tob_auth0_accounts');
        $this->dbMock->method('selectRow')->willReturn(null);

        $result = $this->repo->resolveIdentity('auth0|nosub', 'user@example.com', false);

        $this->assertNull($result);
    }

    public function testResolveIdentityMatchesByConnectionSub(): void
    {
        $userId = wp_insert_user([
            'user_login' => 'tob_auth0_test_sub_' . uniqid(),
            'user_pass' => wp_generate_password(),
            'user_email' => 'subtest_' . uniqid() . '@example.com',
        ]);

        $this->dbMock->method('getTableName')->willReturn('wp_tob_auth0_accounts');
        $this->dbMock->method('selectRow')->willReturn((object) ['user' => $userId]);

        $result = $this->repo->resolveIdentity('auth0|test_resolve', null, null);

        $this->assertInstanceOf(\WP_User::class, $result);
        $this->assertSame($userId, $result->ID);

        wp_delete_user($userId);
    }

    public function testResolveIdentityMatchesByVerifiedEmail(): void
    {
        $email = 'verified_' . uniqid() . '@example.com';
        $userId = wp_insert_user([
            'user_login' => 'tob_auth0_test_email_' . uniqid(),
            'user_pass' => wp_generate_password(),
            'user_email' => $email,
        ]);

        $this->dbMock->method('getTableName')->willReturn('wp_tob_auth0_accounts');
        $this->dbMock->method('selectRow')->willReturn(null);

        $result = $this->repo->resolveIdentity('auth0|unknown_sub', $email, true);

        $this->assertInstanceOf(\WP_User::class, $result);
        $this->assertSame($userId, $result->ID);

        wp_delete_user($userId);
    }

    public function testResolveIdentityReturnsNullForNonexistentEmail(): void
    {
        $this->dbMock->method('getTableName')->willReturn('wp_tob_auth0_accounts');
        $this->dbMock->method('selectRow')->willReturn(null);

        $result = $this->repo->resolveIdentity('auth0|sub', 'nonexistent_' . uniqid() . '@example.com', true);

        $this->assertNull($result);
    }

    protected function tearDown(): void
    {
        wp_cache_flush();
    }
}
