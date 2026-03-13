# tob-auth0

Simplified Auth0 login/logout integration for WordPress. Replaces the wp-auth0 plugin with a lightweight, configuration-via-constants-only approach.

## Requirements

- PHP 8.1+
- WordPress 6.x
- Auth0 PHP SDK (bundled via Composer)

## Installation

### Via Composer

```json
{
    "repositories": [
        {
            "type": "vcs",
            "url": "https://github.com/the-original-body/tob-auth0"
        }
    ],
    "require": {
        "tob/tob-auth0": "dev-dev"
    },
    "extra": {
        "installer-paths": {
            "wp-content/plugins/{$name}/": ["type:wordpress-plugin"]
        }
    }
}
```

### Manual

Clone into `wp-content/plugins/tob-auth0/` and run `composer install`.

### Activation

```bash
wp plugin activate tob-auth0
```

When switching from wp-auth0, deactivate it first:

```bash
wp plugin deactivate wp-auth0
wp plugin activate tob-auth0
```

## Configuration

All configuration is done via constants in `wp-config.php`. No database options, no admin UI.

### Required

```php
define('AUTH0_CLIENT_DOMAIN', 'tenant.eu.auth0.com');
define('AUTH0_CLIENT_ID',     '...');
define('AUTH0_CLIENT_SECRET', '...');
define('AUTH0_COOKIE_SECRET', '...');  // Generate: php -r "echo bin2hex(random_bytes(64));"
```

**Important:** The cookie secret must be a fixed value, not generated dynamically per request. A dynamic secret causes login loops because the SDK cannot decrypt cookies from the previous request.

### Optional — Cookie Settings

```php
define('AUTH0_COOKIE_DOMAIN',   'app.example.com');
define('AUTH0_COOKIE_PATH',     '/');
define('AUTH0_COOKIE_EXPIRES',  (60 * 60 * 24 * 30));  // 30 days
define('AUTH0_COOKIE_SECURE',   true);
define('AUTH0_COOKIE_SAMESITE', 'none');
```

- `COOKIE_DOMAIN` — required for cross-subdomain scenarios
- `COOKIE_SECURE` — must be `true` for HTTPS
- `COOKIE_SAMESITE` — must be `'none'` when Auth0 redirect crosses domains (requires `COOKIE_SECURE=true`)

### Optional — Auth

```php
define('AUTH0_AUDIENCES',      '');     // Comma-separated API audiences
define('AUTH0_ORGANIZATIONS',  '');     // Comma-separated org IDs (org_...)
define('AUTH0_REFRESH_TOKENS', false);  // Use refresh tokens
```

### Optional — Cache

```php
define('AUTH0_TOKEN_CACHE', true);  // JWKS caching via WP Object Cache (default: true)
```

### Optional — Hook Priorities

Override the priority of any registered WordPress hook:

```php
define('AUTH0_ACTION_PRIORITY_INIT', 5);
define('AUTH0_ACTION_PRIORITY_LOGIN_FORM_LOGIN', 10);
```

## Architecture

```
tob-auth0.php              Entry point, singleton via tobAuth0()
src/
  Plugin.php               Core: configuration, SDK, database, registry
  SdkAdapter.php           Wraps Auth0 SDK behind SdkInterface
  Hooks.php                WordPress action/filter registration
  Database.php             DB operations (table creation, queries, migrations)
  AccountRepository.php    Auth0 ↔ WordPress user mapping (CRUD + identity resolution)
  Actions/
    Base.php               Abstract action with hook registry and priority support
    Authentication.php     Login, logout, session pairing, cookie error handling
  Cache/
    WpObjectCachePool.php  PSR-6 cache adapter for JWKS (uses WP Object Cache)
    WpObjectCacheItem.php  PSR-6 cache item
  Contracts/
    SdkInterface.php       Interface for SDK (enables test mocking)
    DatabaseInterface.php  Interface for Database (enables test mocking)
```

## Auth Flow

1. User visits protected page → redirected to `wp-login.php`
2. `onLogin()` clears stale cookies (WP auth, Auth0 SDK, PHP session)
3. Redirect to Auth0 Universal Login (`/authorize`)
4. Auth0 authenticates user → callback to `wp-login.php?code=...&state=...`
5. `exchangeToken()` validates state and exchanges code for tokens
6. `authenticateSession()` resolves Auth0 sub to WordPress user:
   - First: lookup by Auth0 connection (`sub`) in `wp_tob_auth0_accounts`
   - Fallback: lookup by verified email via `get_user_by('email', ...)`
7. Creates account connection, sets WP auth cookie, redirects to `/`

### Session Pairing

On every `init`, the plugin checks that the Auth0 session and WordPress session belong to the same user. Mismatches trigger automatic logout to prevent session hijacking.

### Cookie Cleanup on Login

Before initiating a new Auth0 flow, `onLogin()` automatically clears:
- WordPress auth cookies (`wordpress_sec_*`, `wordpress_logged_in_*`) via `wp_clear_auth_cookie()`
- Auth0 SDK cookies (`auth0_session_*`, `auth0_transient_*`) via `$sdk->clear()`
- PHP session cookie via `session_name()`

This prevents login loops caused by stale cookies from previous sessions or plugin switches.

## Database

### Table: `wp_tob_auth0_accounts`

Maps Auth0 connections to WordPress users.

| Column | Type | Description |
|--------|------|-------------|
| id | BIGINT | Auto-increment PK |
| domain | VARCHAR(255) | Auth0 tenant domain |
| site | TINYINT | WordPress network ID |
| blog | BIGINT | WordPress blog ID |
| user | BIGINT | WordPress user ID |
| auth0 | VARCHAR(255) | Auth0 sub (e.g. `google-oauth2\|123`) |

**Unique constraint:** `(domain, auth0)` — one Auth0 connection per domain.

The table is created automatically on first use. Schema migrations (e.g. TEXT → VARCHAR, adding unique constraint) run via `upgradeTable()` on each `prepDatabase()` call.

## Constant Fallback Chain

The plugin uses a two-level constant lookup for shared values:

| Plugin reads | Falls back to |
|-------------|---------------|
| `AUTH0_DOMAIN` | `AUTH0_CLIENT_DOMAIN` |
| `AUTH0_CLIENT_ID` | `AUTH0_CLIENT_ID` |
| `AUTH0_CLIENT_SECRET` | `AUTH0_CLIENT_SECRET` |

This allows the plugin to share Auth0 credentials with other plugins that use the same constants.

## Testing

```bash
composer install
vendor/bin/phpunit
```

Tests use `DatabaseInterface` and `SdkInterface` mocks — no real Auth0 calls or database queries in unit tests.

## Compatibility with wp-auth0

Both plugins can coexist (only one active at a time). To switch:

```bash
# Switch to tob-auth0
wp plugin deactivate wp-auth0
wp plugin activate tob-auth0

# Switch back to wp-auth0
wp plugin deactivate tob-auth0
wp plugin activate wp-auth0
```
