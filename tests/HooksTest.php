<?php

declare(strict_types=1);

namespace Tests\TobAuth0;

use PHPUnit\Framework\TestCase;
use Tob\Auth0\Hooks;

class HooksTest extends TestCase
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
        $dummy = new class {
            public function callback(): void {}
        };

        $result = $hooks->add('init', $dummy, 'callback');
        $this->assertSame($hooks, $result);
    }

    public function testRemoveReturnsSelf(): void
    {
        $hooks = new Hooks(Hooks::CONST_ACTION_HOOK);
        $dummy = new class {
            public function callback(): void {}
        };

        $result = $hooks->remove('init', $dummy, 'callback');
        $this->assertSame($hooks, $result);
    }

    public function testAddRegistersWordPressAction(): void
    {
        $hooks = new Hooks(Hooks::CONST_ACTION_HOOK);
        $dummy = new class {
            public function myHandler(): void {}
        };

        $hooks->add('tob_auth0_test_action', $dummy, 'myHandler', 15, 2);

        $this->assertSame(
            15,
            has_action('tob_auth0_test_action', [$dummy, 'myHandler'])
        );
    }

    public function testAddRegistersWordPressFilter(): void
    {
        $hooks = new Hooks(Hooks::CONST_ACTION_FILTER);
        $dummy = new class {
            public function myFilter(): string { return 'filtered'; }
        };

        $hooks->add('tob_auth0_test_filter', $dummy, 'myFilter', 20, 1);

        $this->assertSame(
            20,
            has_filter('tob_auth0_test_filter', [$dummy, 'myFilter'])
        );
    }

    public function testRemoveUnregistersWordPressAction(): void
    {
        $hooks = new Hooks(Hooks::CONST_ACTION_HOOK);
        $dummy = new class {
            public function myHandler(): void {}
        };

        $hooks->add('tob_auth0_test_remove', $dummy, 'myHandler', 10, 1);
        $this->assertSame(10, has_action('tob_auth0_test_remove', [$dummy, 'myHandler']));

        $hooks->remove('tob_auth0_test_remove', $dummy, 'myHandler', 10, 1);
        $this->assertFalse(has_action('tob_auth0_test_remove', [$dummy, 'myHandler']));
    }
}
