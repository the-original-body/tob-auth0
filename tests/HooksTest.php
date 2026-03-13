<?php

declare(strict_types=1);

namespace Tests\TobAuth0;

use Tob\Auth0\Hooks;

class HooksTestDummy
{
    public function callback(): void {}
    public function myHandler(): void {}
    public function myFilter(): string { return 'filtered'; }
}

class HooksTest extends WpTestCase
{
    public function testDefaultHookTypeIsAction(): void
    {
        $hooks = new Hooks();
        $this->assertSame(Hooks::CONST_ACTION_HOOK, $hooks->hookType);
    }

    public function testCanSetFilterHookType(): void
    {
        $hooks = new Hooks(Hooks::CONST_ACTION_FILTER);
        $this->assertSame(Hooks::CONST_ACTION_FILTER, $hooks->hookType);
    }

    public function testAddReturnsSelf(): void
    {
        $hooks = new Hooks(Hooks::CONST_ACTION_HOOK);
        $dummy = new HooksTestDummy();

        $result = $hooks->add('init', $dummy, 'callback');
        $this->assertSame($hooks, $result);
    }

    public function testRemoveReturnsSelf(): void
    {
        $hooks = new Hooks(Hooks::CONST_ACTION_HOOK);
        $dummy = new HooksTestDummy();

        $result = $hooks->remove('init', $dummy, 'callback');
        $this->assertSame($hooks, $result);
    }

    public function testAddRegistersWordPressAction(): void
    {
        $hooks = new Hooks(Hooks::CONST_ACTION_HOOK);
        $dummy = new HooksTestDummy();

        $hooks->add('tob_auth0_test_action', $dummy, 'myHandler', 15, 2);

        $this->assertNotFalse(has_action('tob_auth0_test_action'));
    }

    public function testAddRegistersWordPressFilter(): void
    {
        $hooks = new Hooks(Hooks::CONST_ACTION_FILTER);
        $dummy = new HooksTestDummy();

        $hooks->add('tob_auth0_test_filter', $dummy, 'myFilter', 20, 1);

        $this->assertNotFalse(has_filter('tob_auth0_test_filter'));
    }

    public function testRemoveUnregistersWordPressAction(): void
    {
        $hooks = new Hooks(Hooks::CONST_ACTION_HOOK);
        $dummy = new HooksTestDummy();

        $hooks->add('tob_auth0_test_remove', $dummy, 'myHandler', 10, 1);
        $this->assertNotFalse(has_action('tob_auth0_test_remove'));

        $hooks->remove('tob_auth0_test_remove', $dummy, 'myHandler', 10, 1);
        $this->assertFalse(has_action('tob_auth0_test_remove'));
    }
}
