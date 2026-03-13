<?php

declare(strict_types=1);

namespace Tests\TobAuth0;

use Auth0\SDK\Configuration\SdkConfiguration;
use PHPUnit\Framework\TestCase;
use Tob\Auth0\Contracts\SdkInterface;
use Tob\Auth0\Plugin;

class PluginTest extends TestCase
{
    public function testGetConstantReturnsDefinedValue(): void
    {
        if (! defined('AUTH0_TEST_CONST_ABC')) {
            define('AUTH0_TEST_CONST_ABC', 'hello');
        }

        $plugin = new Plugin(null, null);
        $this->assertSame('hello', $plugin->getConstant('TEST_CONST_ABC'));
    }

    public function testGetConstantReturnsDefaultWhenNotDefined(): void
    {
        $plugin = new Plugin(null, null);
        $this->assertSame('fallback', $plugin->getConstant('NONEXISTENT_XYZ_999', 'fallback'));
    }

    public function testGetConstantReturnsNullByDefault(): void
    {
        $plugin = new Plugin(null, null);
        $this->assertNull($plugin->getConstant('NONEXISTENT_XYZ_998'));
    }

    public function testIsReadyReturnsFalseWithoutConfiguration(): void
    {
        $config = new SdkConfiguration(
            strategy: SdkConfiguration::STRATEGY_NONE,
        );

        $plugin = new Plugin(null, $config);
        $this->assertFalse($plugin->isReady());
    }

    public function testIsReadyReturnsTrueWithValidConfiguration(): void
    {
        $config = new SdkConfiguration(
            strategy: SdkConfiguration::STRATEGY_NONE,
            domain: 'test.eu.auth0.com',
            clientId: 'test_client_id',
            clientSecret: 'test_secret',
            cookieSecret: 'cookie_secret_value',
        );

        $plugin = new Plugin(null, $config);
        $this->assertTrue($plugin->isReady());
    }

    public function testIsReadyReturnsFalseWithoutClientId(): void
    {
        $config = new SdkConfiguration(
            strategy: SdkConfiguration::STRATEGY_NONE,
            domain: 'test.eu.auth0.com',
        );

        $plugin = new Plugin(null, $config);
        $this->assertFalse($plugin->isReady());
    }

    public function testIsReadyReturnsFalseWithoutClientSecret(): void
    {
        $config = new SdkConfiguration(
            strategy: SdkConfiguration::STRATEGY_NONE,
            domain: 'test.eu.auth0.com',
            clientId: 'id',
        );

        $plugin = new Plugin(null, $config);
        $this->assertFalse($plugin->isReady());
    }

    public function testIsReadyReturnsFalseWithoutDomain(): void
    {
        $config = new SdkConfiguration(
            strategy: SdkConfiguration::STRATEGY_NONE,
            clientId: 'id',
            clientSecret: 'secret',
        );

        $plugin = new Plugin(null, $config);
        $this->assertFalse($plugin->isReady());
    }

    public function testIsReadyReturnsFalseWithoutCookieSecret(): void
    {
        $config = new SdkConfiguration(
            strategy: SdkConfiguration::STRATEGY_NONE,
            domain: 'test.auth0.com',
            clientId: 'id',
            clientSecret: 'secret',
        );

        $plugin = new Plugin(null, $config);
        $this->assertFalse($plugin->isReady());
    }

    public function testGetSdkReturnsSameInstance(): void
    {
        $sdk = $this->createMock(SdkInterface::class);
        $plugin = new Plugin($sdk, null);

        $this->assertSame($sdk, $plugin->getSdk());
        $this->assertSame($sdk, $plugin->getSdk()); // same instance
    }

    public function testActionsReturnsSingleton(): void
    {
        $plugin = new Plugin(null, null);
        $hooks1 = $plugin->actions();
        $hooks2 = $plugin->actions();

        $this->assertSame($hooks1, $hooks2);
    }
}
