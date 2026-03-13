<?php

declare(strict_types=1);

namespace Tob\Auth0\Contracts;

use Auth0\SDK\Contract\API\ManagementInterface;

interface SdkInterface
{
    public function clear(bool $transient = true): self;

    public function management(): ManagementInterface;

    public function getCredentials(): ?object;

    public function getRequestParameter(string $parameterName, int $filter = FILTER_SANITIZE_FULL_SPECIAL_CHARS, array $filterOptions = []): ?string;

    public function exchange(?string $redirectUri = null, ?string $code = null, ?string $state = null): bool;

    public function login(?string $redirectUrl = null, ?array $params = null): string;

    public function logout(?string $returnUri = null, ?array $params = null): string;

    public function renew(?array $params = null): self;
}
