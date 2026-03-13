<?php

/**
 * Plugin Name:       TOB Auth0
 * Description:       Simplified Auth0 login/logout integration for The Original Body platform. Configuration via constants only.
 * Version:           0.0.1
 * Requires PHP:      8.3
 * Author:            The Original Body
 * License:           MIT
 * Text Domain:       tob-auth0
 *
 * Configuration (wp-config.php):
 *
 * // Required (shared with tob-api — fallback from AUTH0_CLIENT_*)
 * define('AUTH0_CLIENT_DOMAIN',      'the-original-body.eu.auth0.com');
 * define('AUTH0_CLIENT_ID',          '...');
 * define('AUTH0_CLIENT_SECRET',      '...');
 *
 * // Required (tob-auth0 only)
 * define('AUTH0_COOKIE_SECRET',  '...');  // bin2hex(random_bytes(64))
 *
 * // Optional — Auth
 * define('AUTH0_AUDIENCES',          '');          // Comma-separated API audiences
 * define('AUTH0_ORGANIZATIONS',      '');          // Comma-separated org IDs (org_...)
 * define('AUTH0_REFRESH_TOKENS',     false);       // Use refresh tokens
 *
 * // Optional — Cookies
 * define('AUTH0_COOKIE_DOMAIN',   null);
 * define('AUTH0_COOKIE_PATH',     '/');
 * define('AUTH0_COOKIE_EXPIRES',  0);       // TTL in seconds
 * define('AUTH0_COOKIE_SECURE',   true);    // Require HTTPS
 * define('AUTH0_COOKIE_SAMESITE', 'lax');   // 'lax', 'strict', 'none'
 *
 * // Optional — Cache
 * define('AUTH0_TOKEN_CACHE',     true);    // JWKS caching via WP Object Cache
 */

declare(strict_types=1);

use Auth0\SDK\Configuration\SdkConfiguration as Configuration;
use Tob\Auth0\Contracts\SdkInterface;
use Tob\Auth0\Plugin;

define('AUTH0_VERSION', '1.0.0');

// User profile section renders early (before other plugins like Profile Builder)
define('AUTH0_ACTION_PRIORITY_SHOW_USER_PROFILE', 5);
define('AUTH0_ACTION_PRIORITY_EDIT_USER_PROFILE', 5);

if (!defined('ABSPATH')) {
    die;
}

// Composer autoload (Auth0 SDK, Guzzle, plugin classes)
require_once plugin_dir_path(__FILE__) . 'vendor/autoload.php';

tobAuth0()->run();

/**
 * Returns the singleton instance of the TOB Auth0 plugin.
 */
function tobAuth0(
    ?Plugin        $plugin = null,
    ?SdkInterface  $sdk = null,
    ?Configuration $configuration = null,
): Plugin
{
    static $instance = null;

    $instance ??= $plugin ?? new Plugin($sdk, $configuration);

    return $instance;
}
