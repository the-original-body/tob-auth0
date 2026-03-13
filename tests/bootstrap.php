<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/vendor/autoload.php';

// ABSPATH is required by src/Database.php (require_once ABSPATH . 'wp-admin/includes/upgrade.php')
if (!defined('ABSPATH')) {
    define('ABSPATH', __DIR__ . '/wp-stub-root/');
}

// Silence logger output in tests (especially @runInSeparateProcess)
define('AUTH0_LOG_HANDLERS', [new \Monolog\Handler\NullHandler()]);

// Minimal WP_User — only public properties used by the plugin
if (!class_exists('WP_User')) {
    class WP_User
    {
        public int $ID = 0;
        public string $user_login = '';
        public string $user_email = '';
        public string $user_pass = '';
        public string $display_name = '';
        public string $nickname = '';
        public string $user_firstname = '';
        public string $user_lastname = '';
    }
}

// Minimal WP_Error — used as return-type check in AccountRepository::updateEmail
if (!class_exists('WP_Error')) {
    class WP_Error
    {
    }
}
