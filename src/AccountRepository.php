<?php

declare(strict_types=1);

namespace Tob\Auth0;

use Tob\Auth0\Contracts\DatabaseInterface;
use WP_Error;
use WP_User;

final class AccountRepository
{
    private DatabaseInterface $database;

    public function __construct(private Plugin $plugin, ?DatabaseInterface $database = null)
    {
        $this->database = $database ?? $this->plugin->database();
    }

    public function createConnection(WP_User $wpUser, string $connection): void
    {
        $cacheKey = $this->buildCacheKey($connection);

        $found = false;
        wp_cache_get($cacheKey, '', false, $found);

        if ($found || false !== get_transient($cacheKey)) {
            return;
        }

        $table = $this->database->getTableName(Database::CONST_TABLE_ACCOUNTS);
        $domain = $this->getDomain();
        $network = get_current_network_id();
        $blog = get_current_blog_id();

        $this->prepDatabase();

        $existing = $this->database->selectRow('*', $table, 'WHERE `domain` = "%s" AND `user` = %d AND `site` = %d AND `blog` = %d AND `auth0` = "%s" LIMIT 1', [$domain, $wpUser->ID, $network, $blog, $connection]);

        if (null !== $existing) {
            return;
        }

        set_transient($cacheKey, $wpUser->ID, 120);
        wp_cache_set($cacheKey, $wpUser->ID, 120);

        $this->database->insertRow($table, [
            'domain' => $domain,
            'user' => $wpUser->ID,
            'site' => $network,
            'blog' => $blog,
            'auth0' => $connection,
        ], ['%s', '%d', '%d', '%d', '%s']);
    }

    public function getConnections(int $userId): ?array
    {
        $domain = $this->getDomain();
        $table = $this->database->getTableName(Database::CONST_TABLE_ACCOUNTS);
        $network = get_current_network_id();
        $blog = get_current_blog_id();

        $this->prepDatabase();

        $connections = $this->database->selectResults('auth0', $table, 'WHERE `domain` = "%s" AND `site` = %d AND `blog` = %d AND `user` = %d', [$domain, $network, $blog, $userId]);

        return $connections ?: null;
    }

    public function deleteConnections(int $userId): ?array
    {
        $domain = $this->getDomain();
        $table = $this->database->getTableName(Database::CONST_TABLE_ACCOUNTS);
        $network = get_current_network_id();
        $blog = get_current_blog_id();

        $this->prepDatabase();

        $connections = $this->database->selectResults('auth0', $table, 'WHERE `domain` = "%s" AND `site` = %d AND `blog` = %d AND `user` = "%s" LIMIT 1', [$domain, $network, $blog, $userId]);

        if (!$connections) {
            return null;
        }

        $this->database->deleteRow($table, ['domain' => $domain, 'user' => $userId, 'site' => $network, 'blog' => $blog], ['%s', '%d', '%s', '%s']);
        wp_cache_flush();

        return $connections;
    }

    public function findByConnection(string $connection): ?WP_User
    {
        $cacheKey = $this->buildCacheKey($connection);
        $userId = $this->lookupCachedUserId($cacheKey);

        if (null === $userId) {
            $this->prepDatabase();

            $table = $this->database->getTableName(Database::CONST_TABLE_ACCOUNTS);
            $domain = $this->getDomain();
            $network = get_current_network_id();
            $blog = get_current_blog_id();

            $row = $this->database->selectRow('user', $table, 'WHERE `domain` = "%s" AND `site` = %d AND `blog` = %d AND `auth0` = "%s" LIMIT 1', [$domain, $network, $blog, $connection]);

            if (null === $row) {
                return null;
            }

            $userId = $row->user;
        }

        set_transient($cacheKey, $userId, 120);
        wp_cache_set($cacheKey, $userId, 120);

        $user = get_user_by('ID', $userId);

        return $user instanceof WP_User ? $user : null;
    }

    public function resolveIdentity(
        ?string $sub = null,
        ?string $email = null,
        ?bool $verified = null,
    ): ?WP_User {
        $email = sanitize_email(filter_var($email ?? '', FILTER_SANITIZE_EMAIL, FILTER_NULL_ON_FAILURE) ?? '');

        if (null !== $sub) {
            $found = $this->findByConnection(sanitize_text_field($sub));

            if ($found instanceof WP_User) {
                return $found;
            }
        }

        if (true !== $verified || '' === $email) {
            return null;
        }

        $found = get_user_by('email', $email);

        return $found instanceof WP_User ? $found : null;
    }

    public function updateEmail(WP_User $wpUser, string $email): ?WP_User
    {
        if ($wpUser->user_email === $email) {
            return $wpUser;
        }

        $wpUser->user_email = $email;
        $status = wp_update_user($wpUser);

        return $status instanceof WP_Error ? null : $wpUser;
    }

    private function buildCacheKey(string $connection): string
    {
        $domain = $this->getDomain();
        $network = get_current_network_id();
        $blog = get_current_blog_id();

        return 'tob_auth0_account_' . hash('sha256', $domain . '::' . $connection . '::' . $network . '!' . $blog);
    }

    private function getDomain(): string
    {
        return (string) ($this->plugin->getConstant('DOMAIN', '') ?: $this->plugin->getSharedConstant('DOMAIN', ''));
    }

    private function lookupCachedUserId(string $cacheKey): ?int
    {
        $found = false;
        $cached = wp_cache_get($cacheKey, '', false, $found);

        if ($found && $cached) {
            return (int) $cached;
        }

        $transient = get_transient($cacheKey);

        if (false !== $transient) {
            return (int) $transient;
        }

        return null;
    }

    private function prepDatabase(): void
    {
        $cacheKey = 'tob_auth0_db_check_accounts';

        $found = false;
        wp_cache_get($cacheKey, '', false, $found);

        if ($found || false !== get_transient($cacheKey)) {
            return;
        }

        set_transient($cacheKey, true, 1800);
        wp_cache_set($cacheKey, true, 1800);

        $this->database->createTable(Database::CONST_TABLE_ACCOUNTS);
        $this->database->upgradeTable(Database::CONST_TABLE_ACCOUNTS);
    }
}
