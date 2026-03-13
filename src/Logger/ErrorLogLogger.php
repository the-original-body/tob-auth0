<?php

declare(strict_types=1);

namespace Tob\Auth0\Logger;

use Psr\Log\AbstractLogger;
use Stringable;

/**
 * Fallback PSR-3 logger that writes to PHP's error_log().
 * Used when the global monolog() function is not available.
 */
final class ErrorLogLogger extends AbstractLogger
{
    public function __construct(private string $channel = 'auth')
    {
    }

    public function log($level, string|Stringable $message, array $context = []): void
    {
        $contextString = [] !== $context ? ' ' . json_encode($context, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) : '';
        error_log("[tob-auth0] [{$this->channel}.{$level}] {$message}{$contextString}");
    }
}
