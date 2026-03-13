<?php

declare(strict_types=1);

namespace Tob\Auth0;

use Auth0\SDK\Auth0;
use Auth0\SDK\Configuration\SdkConfiguration;
use Monolog\Logger as MonologLogger;
use Psr\Log\LoggerInterface;
use Tob\Auth0\Logger\ErrorLogLogger;
use Tob\Auth0\Actions\{Authentication as AuthenticationActions, Sync as SyncActions, UserProfile as UserProfileActions, Base as Actions};
use Tob\Auth0\Cache\WpObjectCachePool;
use Tob\Auth0\Contracts\SdkInterface;
use Throwable;

use function defined;

final class Plugin
{
    /** @var array<class-string<Actions>> */
    private const array ACTIONS = [AuthenticationActions::class, SyncActions::class, UserProfileActions::class];

    /** @var array */
    private array $registry = [];

    public function __construct(
        private ?SdkInterface $auth0,
        private ?SdkConfiguration $sdkConfiguration,
    ) {
    }

    public function actions(): Hooks
    {
        static $instance = null;

        if (null === $instance) {
            $instance = new Hooks(Hooks::CONST_ACTION_HOOK);
        }

        return $instance;
    }

    public function database(): Database
    {
        static $instance = null;

        if (null === $instance) {
            $instance = new Database();
        }

        return $instance;
    }

    public function getClassInstance(string $class): mixed
    {
        if (!array_key_exists($class, $this->registry)) {
            $this->registry[$class] = new $class($this);
        }

        return $this->registry[$class];
    }

    public function setClassInstance(string $class, mixed $instance): void
    {
        $this->registry[$class] = $instance;
    }

    public function getConfiguration(): SdkConfiguration
    {
        $this->sdkConfiguration ??= $this->importConfiguration();

        return $this->sdkConfiguration;
    }

    public function getConstant(string $name, mixed $default = null): mixed
    {
        $constant = 'AUTH0_' . strtoupper($name);

        if (defined($constant)) {
            return constant($constant);
        }

        return $default;
    }

    public function getSharedConstant(string $name, mixed $default = null): mixed
    {
        $constant = 'AUTH0_CLIENT_' . strtoupper($name);

        if (defined($constant)) {
            return constant($constant);
        }

        return $default;
    }

    public function getSdk(): SdkInterface
    {
        $this->auth0 ??= new SdkAdapter(new Auth0($this->getConfiguration()));

        return $this->auth0;
    }

    public function isReady(): bool
    {
        try {
            $config = $this->getConfiguration();
        } catch (Throwable) {
            return false;
        }

        if (!$config->hasClientId() || '' === (string) $config->getClientId()) {
            return false;
        }

        if (!$config->hasClientSecret() || '' === (string) $config->getClientSecret()) {
            return false;
        }

        if (!$config->hasDomain() || '' === $config->getDomain()) {
            return false;
        }

        if (!$config->hasCookieSecret()) {
            return false;
        }

        return '' !== (string) $config->getCookieSecret();
    }

    public function logger(string $channel = 'auth'): LoggerInterface
    {
        static $loggers = [];

        if (isset($loggers[$channel])) {
            return $loggers[$channel];
        }

        // 1. Plugin-specific handlers via AUTH0_LOG_HANDLERS constant
        $handlers = $this->getConstant('LOG_HANDLERS');

        if (is_array($handlers) && [] !== $handlers) {
            $logger = new MonologLogger($channel);
            foreach ($handlers as $handler) {
                $logger->pushHandler($handler);
            }

            $loggers[$channel] = $logger;

            return $logger;
        }

        // 2. Global monolog() function (mu-plugins/monolog.php)
        if (function_exists('monolog')) {
            $loggers[$channel] = monolog($channel);

            return $loggers[$channel];
        }

        // 3. Fallback: PHP error_log()
        $loggers[$channel] = new ErrorLogLogger($channel);

        return $loggers[$channel];
    }

    public function run(): self
    {
        foreach (self::ACTIONS as $action) {
            $callback = [$this->getClassInstance($action), 'register'];
            /** @var callable $callback */
            $callback();
        }

        return $this;
    }

    private function importConfiguration(): SdkConfiguration
    {
        $domain = $this->getConstant('DOMAIN', '') ?: $this->getSharedConstant('DOMAIN', '');
        $clientId = $this->getConstant('CLIENT_ID', '') ?: $this->getSharedConstant('ID', '');
        $clientSecret = $this->getConstant('CLIENT_SECRET', '') ?: $this->getSharedConstant('SECRET', '');
        $cookieSecret = $this->getConstant('COOKIE_SECRET', '');
        $cookieDomain = $this->getConstant('COOKIE_DOMAIN');
        $cookiePath = $this->getConstant('COOKIE_PATH', '/');
        $cookieExpires = (int) $this->getConstant('COOKIE_EXPIRES', 0);
        $cookieSecure = (bool) $this->getConstant('COOKIE_SECURE', is_ssl());
        $cookieSameSite = $this->getConstant('COOKIE_SAMESITE', 'lax');

        $audiences = $this->getConstant('AUDIENCES');
        $organizations = $this->getConstant('ORGANIZATIONS');

        if (is_string($audiences) && '' !== $audiences) {
            $audiences = array_filter(array_values(array_unique(explode(',', trim($audiences)))));
        } else {
            $audiences = null;
        }

        if (is_string($organizations) && '' !== $organizations) {
            $organizations = array_filter(array_values(array_unique(explode(',', trim($organizations)))));
        } else {
            $organizations = null;
        }

        $sdkConfiguration = new SdkConfiguration(
            strategy: SdkConfiguration::STRATEGY_REGULAR,
            domain: $domain,
            clientId: $clientId,
            redirectUri: get_site_url(null, 'wp-login.php'),
            clientSecret: $clientSecret,
            audience: $audiences,
            organization: $organizations,
            cookieSecret: $cookieSecret,
            cookieDomain: $cookieDomain,
            cookieExpires: $cookieExpires,
            cookiePath: $cookiePath,
            cookieSecure: $cookieSecure,
            cookieSameSite: $cookieSameSite,
        );

        if ($this->getConstant('TOKEN_CACHE', true)) {
            $sdkConfiguration->setTokenCache(new WpObjectCachePool());
        }

        return $sdkConfiguration;
    }
}
