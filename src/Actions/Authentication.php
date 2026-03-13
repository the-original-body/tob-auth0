<?php

declare(strict_types=1);

namespace Tob\Auth0\Actions;

use Tob\Auth0\AccountRepository;
use Throwable;
use WP_User;

final class Authentication extends Base
{
    private const string LOG_CHANNEL = "auth";

    /** @var array<string, array<int, int|string>|string> */
    protected array $registry = [
        'init' => 'onInit',

        'auth_cookie_expiration' => ['onAuthCookieAssignExpiration', 3],
        'auth_cookie_malformed' => ['onAuthCookieMalformed', 2],
        'auth_cookie_expired' => 'onAuthCookieExpired',
        'auth_cookie_bad_username' => 'onAuthCookieBadUsername',
        'auth_cookie_bad_session_token' => 'onAuthCookieBadSessionToken',
        'auth_cookie_bad_hash' => 'onAuthCookieBadHash',

        'login_form_login' => 'onLogin',
        'auth0_login_callback' => 'onLogin',

        'login_form_logout' => 'onLogout',
        'auth0_logout' => 'onLogout',
        'auth0_token_exchange_failed' => 'onExchangeFailed',

        'deleted_user' => 'onDeletedUser',
    ];

    private ?AccountRepository $accountRepository = null;

    public function accounts(?AccountRepository $override = null): AccountRepository
    {
        if (null !== $override) {
            $this->accountRepository = $override;
        }

        return $this->accountRepository ??= new AccountRepository($this->getPlugin());
    }

    public function onAuthCookieAssignExpiration(int $length, int $user_id, bool $remember): int
    {
        if ($remember) {
            $ttl = (int) $this->getPlugin()->getConstant('COOKIE_EXPIRES', 0);

            $this->log(self::LOG_CHANNEL)->debug(
                'onAuthCookieAssignExpiration: Expiration override',
                [
                    'user_id' => $user_id,
                    'remember' => true,
                    'original_ttl' => $length,
                    'configured_ttl' => $ttl,
                    'applied_ttl' => $ttl > 0 ? $ttl : $length,
                ]
            );

            return $ttl > 0 ? $ttl : $length;
        }

        return $length;
    }

    public function onAuthCookieBadHash(array $cookieElements): void
    {
        $this->log(self::LOG_CHANNEL)->debug('onAuthCookieBadHash: Bad hash detected');
        $this->onCookieError();
    }

    public function onAuthCookieBadSessionToken(array $cookieElements): void
    {
        $this->log(self::LOG_CHANNEL)->debug('onAuthCookieBadSessionToken: Bad session token detected');
        $this->onCookieError();
    }

    public function onAuthCookieBadUsername(array $cookieElements): void
    {
        $this->log(self::LOG_CHANNEL)->debug('onAuthCookieBadUsername: Bad username detected');
        $this->onCookieError();
    }

    public function onAuthCookieExpired(array $cookieElements): void
    {
        $this->log(self::LOG_CHANNEL)->debug('onAuthCookieExpired: Cookie expired');
        $this->onCookieError();
    }

    public function onAuthCookieMalformed(string $cookie, ?string $scheme = null): void
    {
        if ('' !== $cookie) {
            $this->log(self::LOG_CHANNEL)->debug(
                'onAuthCookieMalformed: Malformed cookie detected',
                [
                    'scheme' => $scheme,
                ]
            );
            $this->onCookieError();
        }
    }

    public function onDeletedUser($userId): void
    {
        $this->log(self::LOG_CHANNEL)->info(
            'onDeletedUser: Removing Auth0 connections',
            [
                'user_id' => $userId,
            ]
        );
        $this->accounts()->deleteConnections($userId);
    }

    public function onInit(): void
    {
        if (!$this->getPlugin()->isReady()) {
            return;
        }

        if (!is_user_logged_in()) {
            return;
        }

        $session = $this->getSdk()->getCredentials();
        $expired = $session?->accessTokenExpired ?? true;
        $wpUser = wp_get_current_user();

        $this->log(self::LOG_CHANNEL)->debug(
            'onInit: Session check',
            [
                'user_id' => $wpUser->ID,
                'has_session' => null !== $session,
                'expired' => $expired,
                'sub' => $session->user['sub'] ?? null,
            ]
        );

        if (!$expired && (wp_is_json_request() || wp_is_rest_endpoint())) {
            $this->log(self::LOG_CHANNEL)->debug('onInit: Skipped, API/REST request');
            return;
        }

        if ($this->enforceSessionPairing($session, $wpUser)) {
            return;
        }

        if (null !== $session && $expired) {
            $this->log(self::LOG_CHANNEL)->debug('onInit: Session expired, attempting token refresh');
            $this->attemptTokenRefresh();
        }
    }

    public function onLogin(): void
    {
        if (!$this->getPlugin()->isReady()) {
            $this->log(self::LOG_CHANNEL)->debug('onLogin: Skipped, plugin not ready');
            return;
        }

        nocache_headers();

        $code = $this->getSdk()->getRequestParameter('code');
        $state = $this->getSdk()->getRequestParameter('state');
        $error = $this->getSdk()->getRequestParameter('error');

        $auth0CookieNames = array_keys(array_filter(
            $_COOKIE,
            fn ($k) => str_starts_with($k, 'auth0_'),
            ARRAY_FILTER_USE_KEY,
        ));

        $this->log(self::LOG_CHANNEL)->debug(
            'onLogin: Triggered',
            [
                'has_code' => null !== $code,
                'has_state' => null !== $state,
                'has_error' => null !== $error,
                'error_description' => $this->getSdk()->getRequestParameter('error_description'),
                'auth0_cookies' => $auth0CookieNames,
                'wp_cookies' => array_keys(array_filter(
                    $_COOKIE,
                    fn ($k) => str_starts_with($k, 'wordpress_'),
                    ARRAY_FILTER_USE_KEY,
                )),
                'is_ssl' => is_ssl(),
                'redirect_uri' => get_site_url(null, 'wp-login.php'),
                'cookie_domain' => $this->getPlugin()->getConstant('COOKIE_DOMAIN', ''),
                'request_host' => $_SERVER['HTTP_HOST'] ?? null,
                'retry' => $_GET['auth0_retry'] ?? null,
            ]
        );

        if (null !== $code && null !== $state) {
            $this->log(self::LOG_CHANNEL)->debug(
                'onLogin: Callback received, exchanging token',
                [
                    'state_length' => strlen($state),
                    'code_length' => strlen($code),
                    'transient_cookies' => array_filter($auth0CookieNames, fn ($n) => str_starts_with($n, 'auth0_transient')),
                ]
            );

            $session = $this->exchangeToken($code, $state);

            if (null !== $session) {
                $this->authenticateSession($session);
                return;
            }

            $this->log(self::LOG_CHANNEL)->error(
                'onLogin: Token exchange failed, redirecting',
                [
                    'auth0_cookies_remaining' => array_keys(array_filter(
                        $_COOKIE,
                        fn ($k) => str_starts_with($k, 'auth0_'),
                        ARRAY_FILTER_USE_KEY,
                    )),
                ]
            );

            wp_redirect(add_query_arg('auth0_retry', '1', wp_login_url()));
            exit;
        }

        if (null !== $error) {
            $this->log(self::LOG_CHANNEL)->error(
                'onLogin: Auth0 returned error',
                [
                    'error' => $error,
                    'description' => $this->getSdk()->getRequestParameter('error_description'),
                ]
            );
            wp_redirect('/');
            exit;
        }

        // Clear stale session cookies before initiating a new login flow.
        // Preserve transient storage — login() will set fresh state/nonce there.
        wp_clear_auth_cookie();
        $this->getSdk()->clear(false);

        $this->log(self::LOG_CHANNEL)->debug('onLogin: Cleared WP auth cookies and Auth0 session');

        $sessionName = session_name();
        if (isset($_COOKIE[$sessionName])) {
            setcookie($sessionName, '', time() - (60 * 60 * 24 * 2), '/');
            unset($_COOKIE[$sessionName]);
            $this->log(self::LOG_CHANNEL)->debug(
                'onLogin: Cleared PHP session cookie',
                [
                    'name' => $sessionName,
                ]
            );
        }

        $loginUrl = $this->getSdk()->login(null, ['prompt' => 'login']);

        $this->log(self::LOG_CHANNEL)->info(
            'onLogin: Initiating Auth0 redirect',
            [
                'auth0_url' => strtok($loginUrl, '?'),
                'redirect_uri' => get_site_url(null, 'wp-login.php'),
                'cookie_domain' => $this->getPlugin()->getConstant('COOKIE_DOMAIN', ''),
            ]
        );

        wp_redirect($loginUrl);
        exit;
    }

    public function onExchangeFailed(Throwable $e): void
    {
        $this->log(self::LOG_CHANNEL)->error(
            'onExchangeFailed: ' . $e->getMessage(),
            [
                'exception' => get_class($e),
                'file' => $e->getFile(),
                'line' => $e->getLine(),
            ]
        );
        wp_redirect('/');
        exit;
    }

    public function onLogout(): never
    {
        $wpUser = wp_get_current_user();
        $this->log(self::LOG_CHANNEL)->info(
            'onLogout: Initiated',
            [
                'user_id' => $wpUser->ID,
            ]
        );

        $logoutUrl = $this->getSdk()->logout(get_site_url());
        wp_logout();

        $this->log(self::LOG_CHANNEL)->debug(
            'onLogout: WP session destroyed, redirecting to Auth0',
            [
                'auth0_url' => strtok($logoutUrl, '?'),
            ]
        );

        wp_redirect($logoutUrl);
        exit;
    }

    private function attemptTokenRefresh(): void
    {
        if (!$this->getPlugin()->getConstant('REFRESH_TOKENS', false)) {
            $this->log(self::LOG_CHANNEL)->debug('attemptTokenRefresh: Disabled, AUTH0_REFRESH_TOKENS not set');
            return;
        }

        try {
            $this->getSdk()->renew();
            $this->log(self::LOG_CHANNEL)->info('attemptTokenRefresh: Completed');

            return;
        } catch (Throwable $e) {
            $this->log(self::LOG_CHANNEL)->error(
                'attemptTokenRefresh: Failed',
                [
                    'error' => $e->getMessage(),
                    'line' => $e->getLine(),
                    'file' => $e->getFile(),
                ]
            );
        }

        $this->getSdk()->clear();
        wp_logout();
        $this->log(self::LOG_CHANNEL)->info('attemptTokenRefresh: Session cleared after failure');
    }

    private function authenticateSession(object $session): void
    {
        $sub = sanitize_text_field($session->user['sub'] ?? '');
        $email = sanitize_email($session->user['email'] ?? '');
        $verified = $session->user['email_verified'] ?? null;

        $this->log(self::LOG_CHANNEL)->debug(
            'authenticateSession: Triggered',
            [
                'sub' => $sub,
                'email_verified' => $verified,
                'token_type' => $session->accessTokenScope ?? null,
            ]
        );

        if ('' === $email) {
            $email = null;
            $verified = null;
        }

        if (null !== $email && true !== $verified) {
            $this->log(self::LOG_CHANNEL)->warning(
                'authenticateSession: Rejected, email not verified',
                [
                    'sub' => $sub,
                ]
            );
            $this->getSdk()->clear();
            setcookie('auth_error', 'email_not_verified', time() + 60, '/');
            wp_redirect('/');
            exit;
        }

        $wpUser = $this->accounts()->resolveIdentity(sub: $sub, email: $email, verified: $verified);

        if (!$wpUser instanceof WP_User) {
            $this->log(self::LOG_CHANNEL)->warning(
                'authenticateSession: Rejected, WP user not found',
                [
                    'sub' => $sub,
                ]
            );
            $this->getSdk()->clear();
            setcookie('auth_error', 'user_not_found', time() + 60, '/');
            wp_redirect('/');
            exit;
        }

        $this->log(self::LOG_CHANNEL)->debug(
            'authenticateSession: WP user resolved',
            [
                'user_id' => $wpUser->ID,
                'sub' => $sub,
            ]
        );

        if ('' !== $sub) {
            $this->accounts()->createConnection($wpUser, $sub);
            $this->log(self::LOG_CHANNEL)->debug(
                'authenticateSession: Auth0 connection stored',
                [
                    'sub' => $sub,
                    'user_id' => $wpUser->ID,
                ]
            );
        }

        if (null !== $email && true === $verified && $email !== $wpUser->user_email) {
            $this->log(self::LOG_CHANNEL)->info(
                'authenticateSession: Email updated from Auth0',
                [
                    'user_id' => $wpUser->ID,
                ]
            );
            $this->accounts()->updateEmail($wpUser, $email);
        }

        wp_set_current_user($wpUser->ID);
        wp_set_auth_cookie($wpUser->ID, true);
        do_action('wp_login', $wpUser->user_login, $wpUser);

        $this->log(self::LOG_CHANNEL)->info(
            'authenticateSession: Login successful',
            [
                'user_id' => $wpUser->ID,
            ]
        );

        wp_redirect('/');
        exit;
    }

    private function enforceSessionPairing(?object $session, WP_User $wordpress): bool
    {
        if (null === $session && 0 !== $wordpress->ID) {
            $this->log(self::LOG_CHANNEL)->info(
                'enforceSessionPairing: WP session without Auth0, logging out',
                [
                    'user_id' => $wordpress->ID,
                ]
            );
            wp_logout();

            return true;
        }

        if (null !== $session && 0 === $wordpress->ID) {
            $this->log(self::LOG_CHANNEL)->info(
                'enforceSessionPairing: Auth0 session without WP login, clearing SDK',
                [
                    'sub' => $session->user['sub'] ?? null,
                ]
            );
            $this->getSdk()->clear();

            return true;
        }

        if (null === $session) {
            return false;
        }

        $sub = $session->user['sub'] ?? null;

        if (null === $sub) {
            $this->log(self::LOG_CHANNEL)->debug('enforceSessionPairing: No sub in session');
            return false;
        }

        $match = $this->accounts()->findByConnection($sub);

        if (!$match instanceof WP_User || $match->ID !== $wordpress->ID) {
            $this->log(self::LOG_CHANNEL)->warning(
                'enforceSessionPairing: Mismatch, forcing logout',
                [
                    'sub' => $sub,
                    'user_id' => $wordpress->ID,
                    'matched_user_id' => $match instanceof WP_User ? $match->ID : null,
                ]
            );
            $this->getSdk()->clear();
            wp_logout();

            return true;
        }

        $this->log(self::LOG_CHANNEL)->debug(
            'enforceSessionPairing: OK',
            [
                'sub' => $sub,
                'user_id' => $wordpress->ID,
            ]
        );

        return false;
    }

    private function exchangeToken(string $code, string $state): ?object
    {
        $this->log(self::LOG_CHANNEL)->debug(
            'exchangeToken: Exchanging authorization code',
            [
                'state_prefix' => substr($state, 0, 8) . '...',
                'code_prefix' => substr($code, 0, 8) . '...',
            ]
        );

        try {
            $this->getSdk()->exchange(
                code: sanitize_text_field($code),
                state: sanitize_text_field($state),
            );
        } catch (Throwable $throwable) {
            $this->log(self::LOG_CHANNEL)->error(
                'exchangeToken: Failed, ' . $throwable->getMessage(),
                [
                    'exception' => get_class($throwable),
                    'line' => $throwable->getLine(),
                    'file' => $throwable->getFile(),
                    'auth0_cookies' => array_keys(array_filter(
                        $_COOKIE,
                        fn ($k) => str_starts_with($k, 'auth0_'),
                        ARRAY_FILTER_USE_KEY,
                    )),
                ]
            );

            $this->getSdk()->clear();
            $this->clearAuth0Cookies();
            do_action('auth0_token_exchange_failed', $throwable);

            return null;
        }

        $credentials = $this->getSdk()->getCredentials();

        $this->log(self::LOG_CHANNEL)->info(
            'exchangeToken: Completed',
            [
                'sub' => $credentials->user['sub'] ?? null,
            ]
        );

        return $credentials;
    }

    /**
     * Force-delete Auth0 SDK cookies directly in the browser.
     * Fallback for when the SDK's purge() cannot decrypt/find stale cookies
     * (e.g. after a cookie secret rotation).
     */
    private function clearAuth0Cookies(): void
    {
        $cookieDomain = $this->getPlugin()->getConstant('COOKIE_DOMAIN', '') ?: '';
        $cookiePath = $this->getPlugin()->getConstant('COOKIE_PATH', '/') ?: '/';
        $expired = time() - 86400;
        $cleared = [];

        foreach ($_COOKIE as $name => $value) {
            if (str_starts_with($name, 'auth0_')) {
                setcookie($name, '', $expired, $cookiePath, $cookieDomain);
                unset($_COOKIE[$name]);
                $cleared[] = $name;
            }
        }

        if ([] !== $cleared) {
            $this->log(self::LOG_CHANNEL)->debug(
                'clearAuth0Cookies: Force-cleared',
                [
                    'cookies' => $cleared,
                    'domain' => $cookieDomain,
                    'path' => $cookiePath,
                ]
            );
        }
    }

    private function onCookieError(): void
    {
        $this->log(self::LOG_CHANNEL)->debug('onCookieError: Clearing Auth0 SDK session and WP auth cookie');
        $this->getSdk()->clear();
        wp_clear_auth_cookie();
    }
}
