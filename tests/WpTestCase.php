<?php

declare(strict_types=1);

namespace Tests\TobAuth0;

use Brain\Monkey;
use Brain\Monkey\Functions;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\TestCase;

/**
 * Base test case with Brain\Monkey + Mockery integration.
 *
 * Provides common WordPress function stubs so that plugin source code
 * can call WP functions without a real WordPress installation.
 */
abstract class WpTestCase extends TestCase
{
    use MockeryPHPUnitIntegration;

    protected function setUp(): void
    {
        parent::setUp();
        Monkey\setUp();

        // ── Common stubs used across plugin source code ──────────────

        Functions\stubs([
            'get_current_network_id' => 1,
            'get_current_blog_id'    => 1,
            'wp_cache_set'           => true,
            'wp_cache_delete'        => false,
            'wp_cache_flush'         => true,
            'set_transient'          => true,
            'delete_transient'       => true,
            'wp_set_auth_cookie'     => true,
            'wp_generate_password'   => 'stub_password_' . bin2hex(random_bytes(4)),
            'nocache_headers'        => null,
            'is_ssl'                 => true,
            'wp_is_json_request'     => false,
            'wp_is_rest_endpoint'    => false,
            'wp_redirect'            => true,
            'wp_login_url'           => 'https://example.com/wp-login.php',
            'wp_delete_user'         => true,
        ]);

        Functions\when('sanitize_email')->alias(
            fn(string $email) => filter_var($email, FILTER_SANITIZE_EMAIL) ?: ''
        );

        Functions\when('sanitize_text_field')->alias(
            fn(string $str) => trim(strip_tags($str))
        );

        Functions\when('get_site_url')->alias(
            fn(?int $blogId = null, string $path = '') => 'https://example.com' . ($path ? '/' . ltrim($path, '/') : '')
        );

        Functions\when('wp_cache_get')->alias(
            fn() => false
        );

        Functions\when('wp_cache_get_multiple')->alias(
            fn(array $keys) => array_fill_keys($keys, false)
        );

        Functions\when('get_transient')->justReturn(false);

        Functions\when('get_user_by')->justReturn(false);

        Functions\when('is_user_logged_in')->justReturn(false);

        Functions\when('wp_get_current_user')->alias(function () {
            $u = new \WP_User();
            $u->ID = 0;
            return $u;
        });

        Functions\when('wp_set_current_user')->alias(function (int $id) {
            $u = new \WP_User();
            $u->ID = $id;
            return $u;
        });

        Functions\when('wp_logout')->alias(function () {
            // no-op
        });

        Functions\when('wp_clear_auth_cookie')->justReturn(null);

        Functions\when('wp_update_user')->alias(function (object $user) {
            return $user->ID ?? 0;
        });

        Functions\when('wp_insert_user')->justReturn(1);

        Functions\when('maybe_create_table')->justReturn(true);

        Functions\when('current_user_can')->justReturn(true);
    }

    protected function tearDown(): void
    {
        Monkey\tearDown();
        parent::tearDown();
    }

    /**
     * Create a WP_User instance for use in tests (no real WP needed).
     */
    protected function createWpUserObject(
        int $id,
        string $login = '',
        string $email = '',
        string $displayName = '',
        string $firstName = '',
        string $lastName = '',
        string $nickname = '',
    ): \WP_User {
        $user = new \WP_User();
        $user->ID = $id;
        $user->user_login = $login ?: 'testuser_' . $id;
        $user->user_email = $email ?: 'testuser_' . $id . '@example.com';
        $user->display_name = $displayName ?: 'Test User ' . $id;
        $user->user_firstname = $firstName;
        $user->user_lastname = $lastName;
        $user->nickname = $nickname ?: 'testuser' . $id;

        return $user;
    }
}
