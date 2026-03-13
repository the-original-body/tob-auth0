<?php

declare(strict_types=1);

namespace Tests\TobAuth0;

use Auth0\SDK\Configuration\SdkConfiguration;
use PHPUnit\Framework\TestCase;
use Tob\Auth0\AccountRepository;
use Tob\Auth0\Actions\Authentication;
use Tob\Auth0\Contracts\DatabaseInterface;
use Tob\Auth0\Contracts\SdkInterface;
use Tob\Auth0\Plugin;

class AuthenticationTest extends TestCase
{
    private SdkInterface $sdkMock;
    private DatabaseInterface $dbMock;
    private Plugin $plugin;
    private Authentication $auth;

    protected function setUp(): void
    {
        $this->sdkMock = $this->createMock(SdkInterface::class);
        $this->dbMock = $this->createMock(DatabaseInterface::class);

        $config = new SdkConfiguration(
            strategy: SdkConfiguration::STRATEGY_NONE,
            domain: 'test.eu.auth0.com',
            clientId: 'test_id',
            clientSecret: 'test_secret',
            cookieSecret: 'cookie_secret',
        );

        $this->plugin = new Plugin($this->sdkMock, $config);
        $this->auth = new Authentication($this->plugin);
        $this->auth->accounts(new AccountRepository($this->plugin, $this->dbMock));
    }

    public function testCookieExpirationReturnsLengthWhenNotRemember(): void
    {
        $result = $this->auth->onAuthCookieAssignExpiration(3600, 1, false);
        $this->assertSame(3600, $result);
    }

    public function testCookieExpirationReturnsConfiguredTtlWhenRemember(): void
    {
        $result = $this->auth->onAuthCookieAssignExpiration(3600, 1, true);

        $ttl = defined('AUTH0_COOKIE_EXPIRES') ? (int) AUTH0_COOKIE_EXPIRES : 0;

        if ($ttl > 0) {
            $this->assertSame($ttl, $result);
        } else {
            $this->assertSame(3600, $result);
        }
    }

    public function testOnAuthCookieBadHashClearsSdk(): void
    {
        $this->sdkMock->expects($this->once())->method('clear');
        $this->auth->onAuthCookieBadHash(['test']);
    }

    public function testOnAuthCookieBadSessionTokenClearsSdk(): void
    {
        $this->sdkMock->expects($this->once())->method('clear');
        $this->auth->onAuthCookieBadSessionToken(['test']);
    }

    public function testOnAuthCookieBadUsernameClearsSdk(): void
    {
        $this->sdkMock->expects($this->once())->method('clear');
        $this->auth->onAuthCookieBadUsername(['test']);
    }

    public function testOnAuthCookieExpiredClearsSdk(): void
    {
        $this->sdkMock->expects($this->once())->method('clear');
        $this->auth->onAuthCookieExpired(['test']);
    }

    public function testOnAuthCookieMalformedClearsSdkWhenNotEmpty(): void
    {
        $this->sdkMock->expects($this->once())->method('clear');
        $this->auth->onAuthCookieMalformed('some_cookie_value');
    }

    public function testOnAuthCookieMalformedDoesNothingWhenEmpty(): void
    {
        $this->sdkMock->expects($this->never())->method('clear');
        $this->auth->onAuthCookieMalformed('');
    }

    public function testOnInitReturnsEarlyWhenNotReady(): void
    {
        $configNotReady = new SdkConfiguration(
            strategy: SdkConfiguration::STRATEGY_NONE,
        );

        $plugin = new Plugin($this->sdkMock, $configNotReady);
        $auth = new Authentication($plugin);

        $this->sdkMock->expects($this->never())->method('getCredentials');
        $auth->onInit();
    }

    public function testOnInitReturnsEarlyWhenNotLoggedIn(): void
    {
        wp_set_current_user(0);

        $this->sdkMock->expects($this->never())->method('getCredentials');
        $this->auth->onInit();
    }

    public function testOnLoginReturnsEarlyWhenNotReady(): void
    {
        $configNotReady = new SdkConfiguration(
            strategy: SdkConfiguration::STRATEGY_NONE,
        );

        $plugin = new Plugin($this->sdkMock, $configNotReady);
        $auth = new Authentication($plugin);

        $this->sdkMock->expects($this->never())->method('getRequestParameter');
        $auth->onLogin();
    }

    public function testRegisterAddsExpectedHooks(): void
    {
        $this->auth->register();

        $expectedHooks = [
            'init',
            'login_form_login',
            'login_form_logout',
            'auth0_login_callback',
            'auth0_logout',
            'auth_cookie_expired',
            'auth_cookie_bad_hash',
            'auth_cookie_bad_username',
            'auth_cookie_bad_session_token',
            'auth_cookie_malformed',
            'auth_cookie_expiration',
            'auth0_token_exchange_failed',
            'deleted_user',
        ];

        foreach ($expectedHooks as $hook) {
            $this->assertNotFalse(
                has_action($hook),
                "Expected hook '{$hook}' to be registered",
            );
        }
    }

    public function testOnDeletedUserDelegatesDeleteConnections(): void
    {
        $this->dbMock->expects($this->once())
            ->method('getTableName')
            ->willReturn('wp_tob_auth0_accounts');

        $this->dbMock->expects($this->once())
            ->method('selectResults')
            ->willReturn(null);

        $this->auth->onDeletedUser(999);
    }

    protected function tearDown(): void
    {
        wp_cache_flush();
    }
}
