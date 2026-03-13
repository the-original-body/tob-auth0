<?php

declare(strict_types=1);

namespace Tob\Auth0;

use Auth0\SDK\Auth0;
use Auth0\SDK\Contract\API\ManagementInterface;
use Auth0\SDK\Exception\ConfigurationException;
use Auth0\SDK\Exception\NetworkException;
use Auth0\SDK\Exception\StateException;
use Tob\Auth0\Contracts\SdkInterface;

readonly class SdkAdapter implements SdkInterface
{
    public function __construct(private Auth0 $sdk)
    {
    }

    public function clear(bool $transient = true): self
    {
        $this->sdk->clear($transient);

        return $this;
    }

    public function management(): ManagementInterface
    {
        return $this->sdk->management();
    }

    public function getCredentials(): ?object
    {
        return $this->sdk->getCredentials();
    }

    public function getRequestParameter(string $parameterName, int $filter = FILTER_SANITIZE_FULL_SPECIAL_CHARS, array $filterOptions = []): ?string
    {
        return $this->sdk->getRequestParameter($parameterName, $filter, $filterOptions);
    }

    /**
     * @throws NetworkException
     * @throws StateException
     */
    public function exchange(?string $redirectUri = null, ?string $code = null, ?string $state = null): bool
    {
        return $this->sdk->exchange($redirectUri, $code, $state);
    }

    /**
     * @throws ConfigurationException
     */
    public function login(?string $redirectUrl = null, ?array $params = null): string
    {
        return $this->sdk->login($redirectUrl, $params);
    }

    /**
     * @throws ConfigurationException
     */
    public function logout(?string $returnUri = null, ?array $params = null): string
    {
        return $this->sdk->logout($returnUri, $params);
    }

    /**
     * @throws NetworkException
     * @throws StateException
     * @throws ConfigurationException
     */
    public function renew(?array $params = null): self
    {
        $this->sdk->renew($params);

        return $this;
    }
}
