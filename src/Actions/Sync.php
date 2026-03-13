<?php

declare(strict_types=1);

namespace Tob\Auth0\Actions;

use Auth0\SDK\Exception\ArgumentException;
use Auth0\SDK\Exception\NetworkException;
use Auth0\SDK\Utility\HttpResponse;
use Psr\Http\Message\ResponseInterface;
use Random\RandomException;
use WP_User;

final class Sync extends Base
{
    private const string LOG_CHANNEL = "sync";

    protected array $registry = [
        'edit_user_created_user' => ['onCreatedUser', 2],
        'profile_update' => ['onUpdatedUser', 2],
        'password_reset' => ['onPasswordReset', 2],
        'deleted_user' => 'onDeletedUser',
    ];

    /**
     * @throws ArgumentException
     * @throws RandomException
     * @throws NetworkException
     * @throws \JsonException
     */
    public function onCreatedUser(int $userId, $notify = null): void
    {
        $this->log(self::LOG_CHANNEL)->debug(
            'onCreatedUser: Triggered',
            [
                'user_id' => $userId,
                'notify' => $notify,
            ]
        );

        $dbConnection = $this->getDbConnection();

        if (null === $dbConnection) {
            $this->log(self::LOG_CHANNEL)->debug('onCreatedUser: Skipped, no DB connection configured');
            return;
        }

        $user = get_user_by('ID', $userId);
        if (!$user) {
            $this->log(self::LOG_CHANNEL)->debug(
                'onCreatedUser: Skipped, WP user not found',
                [
                    'user_id' => $userId,
                ]
            );
            return;
        }

        $this->log(self::LOG_CHANNEL)->debug(
            'onCreatedUser: Checking if user exists in Auth0',
            [
                'user_id' => $userId,
            ]
        );

        $exists = $this->getResults($this->getSdk()->management()->usersByEmail()->get($user->user_email));
        if (is_array($exists) && [] !== $exists) {
            $this->log(self::LOG_CHANNEL)->info(
                'onCreatedUser: Skipped, user already exists in Auth0',
                [
                    'user_id' => $userId,
                    'auth0_count' => count($exists),
                ]
            );
            return;
        }

        $dbConnectionName = $this->getDatabaseName($dbConnection);
        if (null === $dbConnectionName) {
            $this->log(self::LOG_CHANNEL)->error(
                'onCreatedUser: Failed, could not resolve DB connection name',
                [
                    'user_id' => $userId,
                    'db_connection' => $dbConnection,
                ]
            );
            return;
        }

        $this->log(self::LOG_CHANNEL)->debug(
            'onCreatedUser: Creating Auth0 user',
            [
                'user_id' => $userId,
                'db_connection' => $dbConnectionName,
            ]
        );

        $response = $this->getSdk()->management()->users()->create($dbConnectionName, [
            'name' => $user->display_name,
            'nickname' => $user->nickname,
            'given_name' => $user->user_firstname,
            'family_name' => $user->user_lastname,
            'email' => $user->user_email,
            'email_verified' => true,
            'password' => wp_generate_password(random_int(12, 123), true, true),
        ]);

        $this->logResponse('onCreatedUser', $response, $userId);

        $result = $this->getResults($response, 201);
        if (null === $result) {
            $this->log(self::LOG_CHANNEL)->error(
                'onCreatedUser: Failed, Auth0 API did not return user',
                [
                    'user_id' => $userId,
                ]
            );
            return;
        }

        $auth0Id = $result['user_id'];

        $this->getPlugin()
            ->getClassInstance(Authentication::class)
            ->accounts()
            ->createConnection($user, $auth0Id);

        $this->log(self::LOG_CHANNEL)->debug(
            'onCreatedUser: Local connection stored',
            [
                'user_id' => $userId,
                'auth0_id' => $auth0Id,
            ]
        );

        $this->getSdk()->management()->tickets()->createPasswordChange([
            'user_id' => $auth0Id,
        ]);

        $this->log(self::LOG_CHANNEL)->info(
            'onCreatedUser: Completed, password change ticket sent',
            [
                'user_id' => $userId,
                'auth0_id' => $auth0Id,
            ]
        );
    }

    /**
     * @throws NetworkException
     * @throws ArgumentException
     * @throws \JsonException
     */
    public function createUserWithPassword(int $userId, string $plainPassword): void
    {
        $this->log(self::LOG_CHANNEL)->debug(
            'createUserWithPassword: Triggered',
            [
                'user_id' => $userId,
            ]
        );

        $dbConnection = $this->getDbConnection();

        if (null === $dbConnection) {
            $this->log(self::LOG_CHANNEL)->debug('createUserWithPassword: Skipped, no DB connection configured');
            return;
        }

        $user = get_user_by('ID', $userId);
        if (!$user) {
            $this->log(self::LOG_CHANNEL)->debug(
                'createUserWithPassword: Skipped, WP user not found',
                [
                    'user_id' => $userId,
                ]
            );
            return;
        }

        $this->log(self::LOG_CHANNEL)->debug(
            'createUserWithPassword: Checking if user exists in Auth0',
            [
                'user_id' => $userId,
            ]
        );

        $exists = $this->getResults($this->getSdk()->management()->usersByEmail()->get($user->user_email));
        if (is_array($exists) && [] !== $exists) {
            $this->log(self::LOG_CHANNEL)->info(
                'createUserWithPassword: Skipped, user already exists in Auth0',
                [
                    'user_id' => $userId,
                    'auth0_count' => count($exists),
                ]
            );
            return;
        }

        $dbConnectionName = $this->getDatabaseName($dbConnection);
        if (null === $dbConnectionName) {
            $this->log(self::LOG_CHANNEL)->error(
                'createUserWithPassword: Failed, could not resolve DB connection name',
                [
                    'user_id' => $userId,
                    'db_connection' => $dbConnection,
                ]
            );
            return;
        }

        $this->log(self::LOG_CHANNEL)->debug(
            'createUserWithPassword: Creating Auth0 user',
            [
                'user_id' => $userId,
                'db_connection' => $dbConnectionName,
            ]
        );

        $response = $this->getSdk()->management()->users()->create($dbConnectionName, [
            'name' => $user->display_name,
            'nickname' => $user->nickname,
            'given_name' => $user->user_firstname,
            'family_name' => $user->user_lastname,
            'email' => $user->user_email,
            'email_verified' => true,
            'password' => trim($plainPassword),
        ]);

        $this->logResponse('createUserWithPassword', $response, $userId);

        $result = $this->getResults($response, 201);
        if (null === $result) {
            $this->log(self::LOG_CHANNEL)->error(
                'createUserWithPassword: Failed, Auth0 API did not return user',
                [
                    'user_id' => $userId,
                ]
            );
            return;
        }

        $auth0Id = $result['user_id'];

        $this->getPlugin()
            ->getClassInstance(Authentication::class)
            ->accounts()
            ->createConnection($user, $auth0Id);

        $this->log(self::LOG_CHANNEL)->info(
            'createUserWithPassword: Completed',
            [
                'user_id' => $userId,
                'auth0_id' => $auth0Id,
            ]
        );
    }

    /**
     * @throws ArgumentException
     * @throws NetworkException
     * @throws \JsonException
     */
    public function onUpdatedUser(int $userId, $previousUserData = null): void
    {
        $this->log(self::LOG_CHANNEL)->debug(
            'onUpdatedUser: Triggered',
            [
                'user_id' => $userId,
            ]
        );

        $user = get_user_by('ID', $userId);
        if (!$user) {
            $this->log(self::LOG_CHANNEL)->debug(
                'onUpdatedUser: Skipped, WP user not found',
                [
                    'user_id' => $userId,
                ]
            );
            return;
        }

        $accounts = $this->getPlugin()
            ->getClassInstance(Authentication::class)
            ->accounts();

        $connections = $accounts->getConnections($userId);
        if (null === $connections || [] === $connections) {
            $this->log(self::LOG_CHANNEL)->debug(
                'onUpdatedUser: Skipped, no Auth0 connections found',
                [
                    'user_id' => $userId,
                ]
            );
            return;
        }

        $plainPassword = $_POST['pass1'] ?? null;

        $this->log(self::LOG_CHANNEL)->debug(
            'onUpdatedUser: Processing connections',
            [
                'user_id' => $userId,
                'connection_count' => count($connections),
                'has_password' => ! empty($plainPassword),
            ]
        );

        foreach ($connections as $connection) {
            $this->log(self::LOG_CHANNEL)->debug(
                'onUpdatedUser: Fetching Auth0 user',
                [
                    'auth0_id' => $connection->auth0,
                ]
            );

            $api = $this->getResults($this->getSdk()->management()->users()->get($connection->auth0));
            if (null === $api) {
                $this->log(self::LOG_CHANNEL)->error(
                    'onUpdatedUser: Failed, could not fetch Auth0 user',
                    [
                        'user_id' => $userId,
                        'auth0_id' => $connection->auth0,
                    ]
                );
                continue;
            }

            $connectionId = $api['user_id'] ?? null;
            if (null === $connectionId) {
                $this->log(self::LOG_CHANNEL)->error(
                    'onUpdatedUser: Failed, Auth0 response missing user_id',
                    [
                        'user_id' => $userId,
                        'auth0_id' => $connection->auth0,
                    ]
                );
                continue;
            }

            $currentEmail = $api['email'] ?? '';
            $userMetadata = apply_filters('tob_auth0_sync_user_metadata', [], $user, 'update');

            $updateData = [
                'name' => $user->display_name,
                'nickname' => $user->nickname,
                'given_name' => $user->user_firstname,
                'family_name' => $user->user_lastname,
                'email' => $user->user_email,
                'email_verified' => true,
                'user_metadata' => $userMetadata,
            ];

            if (!empty($plainPassword)) {
                $updateData['password'] = $plainPassword;
            }

            $this->log(self::LOG_CHANNEL)->debug(
                'onUpdatedUser: Updating Auth0 user',
                [
                    'user_id' => $userId,
                    'auth0_id' => $connectionId,
                    'email_changed' => $user->user_email !== $currentEmail,
                    'password_changed' => ! empty($plainPassword),
                    'fields' => array_keys($updateData),
                ]
            );

            $response = $this->getSdk()->management()->users()->update($connectionId, $updateData);
            $this->logResponse('onUpdatedUser', $response, $userId);

            if ($this->getPlugin()->getConstant('SYNC_EMAIL_VERIFICATION', false) && $user->user_email !== $currentEmail) {
                $this->log(self::LOG_CHANNEL)->debug(
                    'onUpdatedUser: Sending email verification ticket',
                    [
                        'user_id' => $userId,
                        'auth0_id' => $connectionId,
                    ]
                );
                $response = $this->getSdk()->management()->tickets()->createEmailVerification($connectionId);
                $this->logResponse('onUpdatedUser: Email verification ticket', $response, $userId);
            }
        }

        $this->log(self::LOG_CHANNEL)->info(
            'onUpdatedUser: Completed',
            [
                'user_id' => $userId,
                'connections_processed' => count($connections),
            ]
        );
    }

    public function onPasswordReset(WP_User $user, string $newPassword): void
    {
        $this->log(self::LOG_CHANNEL)->debug(
            'onPasswordReset: Triggered',
            [
                'user_id' => $user->ID,
            ]
        );
        $this->updatePassword($user->ID, $newPassword);
    }

    /**
     * @throws NetworkException
     * @throws ArgumentException
     */
    public function onDeletedUser(int $userId): void
    {
        $this->log(self::LOG_CHANNEL)->debug(
            'onDeletedUser: Triggered',
            [
                'user_id' => $userId,
            ]
        );

        $accounts = $this->getPlugin()
            ->getClassInstance(Authentication::class)
            ->accounts();

        $connections = $accounts->deleteConnections($userId);
        if (null === $connections || [] === $connections) {
            $this->log(self::LOG_CHANNEL)->debug(
                'onDeletedUser: Skipped, no Auth0 connections found',
                [
                    'user_id' => $userId,
                ]
            );
            return;
        }

        $this->log(self::LOG_CHANNEL)->debug(
            'onDeletedUser: Processing connections',
            [
                'user_id' => $userId,
                'connection_count' => count($connections),
            ]
        );

        foreach ($connections as $connection) {
            $api = $this->getResults($this->getSdk()->management()->users()->get($connection->auth0));
            if (null === $api) {
                $this->log(self::LOG_CHANNEL)->error(
                    'onDeletedUser: Failed, could not fetch Auth0 user',
                    [
                        'user_id' => $userId,
                        'auth0_id' => $connection->auth0,
                    ]
                );
                continue;
            }

            $this->log(self::LOG_CHANNEL)->debug(
                'onDeletedUser: Deleting Auth0 user',
                [
                    'user_id' => $userId,
                    'auth0_id' => $connection->auth0,
                ]
            );

            $response = $this->getSdk()->management()->users()->delete($connection->auth0);
            $this->logResponse('onDeletedUser', $response, $userId);
        }

        $this->log(self::LOG_CHANNEL)->info(
            'onDeletedUser: Completed',
            [
                'user_id' => $userId,
                'connections_deleted' => count($connections),
            ]
        );
    }

    public function updatePassword(int $userId, string $plainPassword): void
    {
        $this->log(self::LOG_CHANNEL)->debug(
            'updatePassword: Triggered',
            [
                'user_id' => $userId,
            ]
        );

        $user = get_user_by('ID', $userId);
        if (!$user) {
            $this->log(self::LOG_CHANNEL)->debug(
                'updatePassword: Skipped, WP user not found',
                [
                    'user_id' => $userId,
                ]
            );
            return;
        }

        $accounts = $this->getPlugin()
            ->getClassInstance(Authentication::class)
            ->accounts();

        $connections = $accounts->getConnections($userId);
        if (null === $connections || [] === $connections) {
            $this->log(self::LOG_CHANNEL)->debug(
                'updatePassword: Skipped, no Auth0 connections found',
                [
                    'user_id' => $userId,
                ]
            );
            return;
        }

        $this->log(self::LOG_CHANNEL)->debug(
            'updatePassword: Processing connections',
            [
                'user_id' => $userId,
                'connection_count' => count($connections),
            ]
        );

        foreach ($connections as $connection) {
            $api = $this->getResults($this->getSdk()->management()->users()->get($connection->auth0));
            if (null === $api) {
                $this->log(self::LOG_CHANNEL)->error(
                    'updatePassword: Failed, could not fetch Auth0 user',
                    [
                        'user_id' => $userId,
                        'auth0_id' => $connection->auth0,
                    ]
                );
                continue;
            }

            $connectionId = $api['user_id'] ?? null;
            if (null === $connectionId) {
                $this->log(self::LOG_CHANNEL)->error(
                    'updatePassword: Failed, Auth0 response missing user_id',
                    [
                        'user_id' => $userId,
                        'auth0_id' => $connection->auth0,
                    ]
                );
                continue;
            }

            $this->log(self::LOG_CHANNEL)->debug(
                'updatePassword: Updating Auth0 password',
                [
                    'user_id' => $userId,
                    'auth0_id' => $connectionId,
                ]
            );

            $response = $this->getSdk()->management()->users()->update($connectionId, [
                'password' => $plainPassword,
            ]);

            $this->logResponse('updatePassword', $response, $userId);
        }

        $this->log(self::LOG_CHANNEL)->info(
            'updatePassword: Completed',
            [
                'user_id' => $userId,
                'connections_processed' => count($connections),
            ]
        );
    }

    private function getDbConnection(): ?string
    {
        $connection = $this->getPlugin()->getConstant('SYNC_DB_CONNECTION');

        $this->log(self::LOG_CHANNEL)->debug(
            'getDbConnection: Resolving',
            [
                'configured' => is_string($connection) && '' !== $connection,
                'value' => is_string($connection) ? substr($connection, 0, 10) . '...' : null,
            ]
        );

        return is_string($connection) && '' !== $connection ? $connection : null;
    }

    /**
     * @throws NetworkException
     * @throws ArgumentException
     * @throws \JsonException
     */
    private function getDatabaseName(string $dbConnection): ?string
    {
        $this->log(self::LOG_CHANNEL)->debug(
            'getDatabaseName: Resolving connection',
            [
                'db_connection' => $dbConnection,
            ]
        );

        $response = $this->getResults($this->getSdk()->management()->connections()->get($dbConnection));
        $name = $response['name'] ?? null;

        if (null === $name) {
            $this->log(self::LOG_CHANNEL)->error(
                'getDatabaseName: Failed, could not resolve connection name',
                [
                    'db_connection' => $dbConnection,
                ]
            );
        } else {
            $this->log(self::LOG_CHANNEL)->debug(
                'getDatabaseName: Resolved',
                [
                    'db_connection' => $dbConnection,
                    'name' => $name,
                ]
            );
        }

        return $name;
    }

    /**
     * @throws \JsonException
     */
    private function getResults(ResponseInterface $response, int $expectedStatusCode = 200): ?array
    {
        if (HttpResponse::wasSuccessful($response, $expectedStatusCode)) {
            return HttpResponse::decodeContent($response);
        }

        $this->log(self::LOG_CHANNEL)->debug(
            'getResults: Unexpected status code',
            [
                'expected' => $expectedStatusCode,
                'actual' => $response->getStatusCode(),
            ]
        );

        return null;
    }

    private function logResponse(string $method, ResponseInterface $response, int $userId): void
    {
        $statusCode = $response->getStatusCode();

        if ($statusCode >= 200 && $statusCode < 300) {
            $this->log(self::LOG_CHANNEL)->info(
                "{$method}: HTTP {$statusCode}",
                [
                    'user_id' => $userId,
                ]
            );

            return;
        }

        $this->log(self::LOG_CHANNEL)->error(
            "{$method}: HTTP {$statusCode}",
            [
                'user_id' => $userId,
                'http_status' => $statusCode,
                'response' => $response->getBody()->getContents(),
            ]
        );
    }
}
