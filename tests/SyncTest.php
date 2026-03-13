<?php

declare(strict_types=1);

namespace Tests\TobAuth0;

use Auth0\SDK\Configuration\SdkConfiguration;
use Auth0\SDK\Contract\API\Management\ConnectionsInterface;
use Auth0\SDK\Contract\API\Management\TicketsInterface;
use Auth0\SDK\Contract\API\Management\UsersByEmailInterface;
use Auth0\SDK\Contract\API\Management\UsersInterface;
use Auth0\SDK\Contract\API\ManagementInterface;
use Brain\Monkey\Functions;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;
use Tob\Auth0\AccountRepository;
use Tob\Auth0\Actions\Authentication;
use Tob\Auth0\Actions\Sync;
use Tob\Auth0\Contracts\DatabaseInterface;
use Tob\Auth0\Contracts\SdkInterface;
use Tob\Auth0\Plugin;
use WP_User;

class SyncTest extends WpTestCase
{
    private SdkInterface&MockObject $sdkMock;
    private DatabaseInterface&MockObject $dbMock;
    private ManagementInterface&MockObject $managementMock;
    private UsersInterface&MockObject $usersMock;
    private UsersByEmailInterface&MockObject $usersByEmailMock;
    private ConnectionsInterface&MockObject $connectionsMock;
    private TicketsInterface&MockObject $ticketsMock;
    private Sync $sync;
    private Authentication $auth;

    /** @var array<int, WP_User> Users created during the test */
    private array $wpUsers = [];

    protected function setUp(): void
    {
        parent::setUp();

        $this->sdkMock = $this->createMock(SdkInterface::class);
        $this->dbMock = $this->createMock(DatabaseInterface::class);
        $this->managementMock = $this->createMock(ManagementInterface::class);
        $this->usersMock = $this->createMock(UsersInterface::class);
        $this->usersByEmailMock = $this->createMock(UsersByEmailInterface::class);
        $this->connectionsMock = $this->createMock(ConnectionsInterface::class);
        $this->ticketsMock = $this->createMock(TicketsInterface::class);

        $this->sdkMock->method('management')->willReturn($this->managementMock);
        $this->managementMock->method('users')->willReturn($this->usersMock);
        $this->managementMock->method('usersByEmail')->willReturn($this->usersByEmailMock);
        $this->managementMock->method('connections')->willReturn($this->connectionsMock);
        $this->managementMock->method('tickets')->willReturn($this->ticketsMock);

        $config = new SdkConfiguration(
            strategy: SdkConfiguration::STRATEGY_NONE,
            domain: 'test.eu.auth0.com',
            clientId: 'test_id',
            clientSecret: 'test_secret',
            cookieSecret: 'cookie_secret',
        );

        $plugin = new Plugin($this->sdkMock, $config);

        $this->auth = new Authentication($plugin);
        $this->auth->accounts(new AccountRepository($plugin, $this->dbMock));
        $plugin->setClassInstance(Authentication::class, $this->auth);

        $this->sync = new Sync($plugin);

        // Stub get_user_by to look up from our in-memory user store
        Functions\when('get_user_by')->alias(function (string $field, mixed $value) {
            if ($field === 'ID') {
                return $this->wpUsers[(int) $value] ?? false;
            }
            foreach ($this->wpUsers as $user) {
                if ($field === 'email' && $user->user_email === $value) {
                    return $user;
                }
            }
            return false;
        });
    }

    public function testRegisterAddsExpectedHooks(): void
    {
        $this->sync->register();

        $this->assertNotFalse(has_action('edit_user_created_user'));
        $this->assertNotFalse(has_action('profile_update'));
        $this->assertNotFalse(has_action('password_reset'));
        $this->assertNotFalse(has_action('deleted_user'));
    }

    public function testOnCreatedUserSkipsWhenNoDbConnection(): void
    {
        // AUTH0_SYNC_DB_CONNECTION not defined → getDbConnection returns null
        $this->usersByEmailMock->expects($this->never())->method('get');
        $this->usersMock->expects($this->never())->method('create');

        $this->sync->onCreatedUser(99);
    }

    public function testOnCreatedUserSkipsWhenUserNotFound(): void
    {
        if (! defined('AUTH0_SYNC_DB_CONNECTION')) {
            define('AUTH0_SYNC_DB_CONNECTION', 'con_test123');
        }

        // User ID that doesn't exist → get_user_by returns false
        $this->usersByEmailMock->expects($this->never())->method('get');
        $this->usersMock->expects($this->never())->method('create');

        $this->sync->onCreatedUser(999999);
    }

    public function testOnCreatedUserSkipsWhenAuth0UserAlreadyExists(): void
    {
        $user = $this->createWpUser(100);

        $this->usersByEmailMock->expects($this->once())
            ->method('get')
            ->with($user->user_email)
            ->willReturn($this->makeResponse(200, [['user_id' => 'auth0|existing']]));

        $this->usersMock->expects($this->never())->method('create');

        $this->sync->onCreatedUser($user->ID);
    }

    public function testOnCreatedUserCreatesAuth0User(): void
    {
        $user = $this->createWpUser(101);

        $this->usersByEmailMock->method('get')
            ->willReturn($this->makeResponse(200, []));

        $this->connectionsMock->method('get')
            ->willReturn($this->makeResponse(200, ['name' => 'Username-Password-Authentication']));

        $createResponse = $this->makeResponse(201, ['user_id' => 'auth0|new123']);
        $this->usersMock->expects($this->once())
            ->method('create')
            ->willReturn($createResponse);

        $this->dbMock->method('getTableName')->willReturn('wp_tob_auth0_accounts');
        $this->dbMock->method('selectRow')->willReturn(null);
        $this->dbMock->method('insertRow')->willReturn(true);

        $this->ticketsMock->expects($this->once())
            ->method('createPasswordChange')
            ->with($this->callback(fn ($data) => $data['user_id'] === 'auth0|new123'))
            ->willReturn($this->makeResponse(201, []));

        $this->sync->onCreatedUser($user->ID);
    }

    public function testCreateUserWithPasswordUsesProvidedPassword(): void
    {
        $user = $this->createWpUser(102);

        $this->usersByEmailMock->method('get')
            ->willReturn($this->makeResponse(200, []));

        $this->connectionsMock->method('get')
            ->willReturn($this->makeResponse(200, ['name' => 'Username-Password-Authentication']));

        $this->usersMock->expects($this->once())
            ->method('create')
            ->with(
                'Username-Password-Authentication',
                $this->callback(fn ($data) => $data['password'] === 'MySecret123!')
            )
            ->willReturn($this->makeResponse(201, ['user_id' => 'auth0|pwd123']));

        $this->dbMock->method('getTableName')->willReturn('wp_tob_auth0_accounts');
        $this->dbMock->method('selectRow')->willReturn(null);
        $this->dbMock->method('insertRow')->willReturn(true);

        // No password change ticket when password is explicitly provided
        $this->ticketsMock->expects($this->never())->method('createPasswordChange');

        $this->sync->createUserWithPassword($user->ID, 'MySecret123!');
    }

    public function testOnUpdatedUserSyncsProfileToAuth0(): void
    {
        $user = $this->createWpUser(103);

        $connectionObj = (object) ['auth0' => 'auth0|upd123'];
        $this->dbMock->method('getTableName')->willReturn('wp_tob_auth0_accounts');
        $this->dbMock->method('selectResults')->willReturn([$connectionObj]);

        $this->usersMock->method('get')
            ->with('auth0|upd123')
            ->willReturn($this->makeResponse(200, [
                'user_id' => 'auth0|upd123',
                'email' => $user->user_email,
            ]));

        $this->usersMock->expects($this->once())
            ->method('update')
            ->with(
                'auth0|upd123',
                $this->callback(fn ($data) => $data['name'] === $user->display_name
                    && $data['email'] === $user->user_email
                    && ! isset($data['password']))
            )
            ->willReturn($this->makeResponse(200, []));

        $this->sync->onUpdatedUser($user->ID);
    }

    public function testOnUpdatedUserIncludesPasswordWhenPostPass1Set(): void
    {
        $user = $this->createWpUser(104);

        $_POST['pass1'] = 'NewPassword456!';

        $connectionObj = (object) ['auth0' => 'auth0|pwd456'];
        $this->dbMock->method('getTableName')->willReturn('wp_tob_auth0_accounts');
        $this->dbMock->method('selectResults')->willReturn([$connectionObj]);

        $this->usersMock->method('get')
            ->willReturn($this->makeResponse(200, [
                'user_id' => 'auth0|pwd456',
                'email' => $user->user_email,
            ]));

        $this->usersMock->expects($this->once())
            ->method('update')
            ->with(
                'auth0|pwd456',
                $this->callback(fn ($data) => $data['password'] === 'NewPassword456!')
            )
            ->willReturn($this->makeResponse(200, []));

        $this->sync->onUpdatedUser($user->ID);

        unset($_POST['pass1']);
    }

    public function testOnUpdatedUserSkipsEmailVerificationWhenConstantNotSet(): void
    {
        $user = $this->createWpUser(105);

        $connectionObj = (object) ['auth0' => 'auth0|emailnotset'];
        $this->dbMock->method('getTableName')->willReturn('wp_tob_auth0_accounts');
        $this->dbMock->method('selectResults')->willReturn([$connectionObj]);

        $this->usersMock->method('get')
            ->willReturn($this->makeResponse(200, [
                'user_id' => 'auth0|emailnotset',
                'email' => 'old@example.com',
            ]));

        $this->usersMock->method('update')
            ->willReturn($this->makeResponse(200, []));

        $this->ticketsMock->expects($this->never())
            ->method('createEmailVerification');

        $this->sync->onUpdatedUser($user->ID);
    }

    /**
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testOnUpdatedUserSkipsEmailVerificationWhenConstantFalse(): void
    {
        define('AUTH0_SYNC_EMAIL_VERIFICATION', false);

        $user = $this->createWpUser(105);

        $connectionObj = (object) ['auth0' => 'auth0|emailfalse'];
        $this->dbMock->method('getTableName')->willReturn('wp_tob_auth0_accounts');
        $this->dbMock->method('selectResults')->willReturn([$connectionObj]);

        $this->usersMock->method('get')
            ->willReturn($this->makeResponse(200, [
                'user_id' => 'auth0|emailfalse',
                'email' => 'old@example.com',
            ]));

        $this->usersMock->method('update')
            ->willReturn($this->makeResponse(200, []));

        $this->ticketsMock->expects($this->never())
            ->method('createEmailVerification');

        $this->sync->onUpdatedUser($user->ID);
    }

    /**
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testOnUpdatedUserTriggersEmailVerificationOnEmailChange(): void
    {
        define('AUTH0_SYNC_EMAIL_VERIFICATION', true);

        $user = $this->createWpUser(105);

        $connectionObj = (object) ['auth0' => 'auth0|email123'];
        $this->dbMock->method('getTableName')->willReturn('wp_tob_auth0_accounts');
        $this->dbMock->method('selectResults')->willReturn([$connectionObj]);

        $this->usersMock->method('get')
            ->willReturn($this->makeResponse(200, [
                'user_id' => 'auth0|email123',
                'email' => 'old@example.com',
            ]));

        $this->usersMock->method('update')
            ->willReturn($this->makeResponse(200, []));

        $this->ticketsMock->expects($this->once())
            ->method('createEmailVerification')
            ->with('auth0|email123')
            ->willReturn($this->makeResponse(201, []));

        $this->sync->onUpdatedUser($user->ID);
    }

    public function testOnUpdatedUserSkipsWhenNoConnections(): void
    {
        $user = $this->createWpUser(106);

        $this->dbMock->method('getTableName')->willReturn('wp_tob_auth0_accounts');
        $this->dbMock->method('selectResults')->willReturn(null);

        $this->usersMock->expects($this->never())->method('get');
        $this->usersMock->expects($this->never())->method('update');

        $this->sync->onUpdatedUser($user->ID);
    }

    public function testOnPasswordResetDelegatesToUpdatePassword(): void
    {
        $user = $this->createWpUser(107);

        $connectionObj = (object) ['auth0' => 'auth0|reset789'];
        $this->dbMock->method('getTableName')->willReturn('wp_tob_auth0_accounts');
        $this->dbMock->method('selectResults')->willReturn([$connectionObj]);

        $this->usersMock->method('get')
            ->willReturn($this->makeResponse(200, [
                'user_id' => 'auth0|reset789',
            ]));

        $this->usersMock->expects($this->once())
            ->method('update')
            ->with(
                'auth0|reset789',
                $this->callback(fn ($data) => $data['password'] === 'ResetPass789!')
            )
            ->willReturn($this->makeResponse(200, []));

        $this->sync->onPasswordReset($user, 'ResetPass789!');
    }

    public function testOnDeletedUserDeletesAuth0Account(): void
    {
        $connectionObj = (object) ['auth0' => 'auth0|del456'];
        $this->dbMock->method('getTableName')->willReturn('wp_tob_auth0_accounts');
        $this->dbMock->method('selectResults')->willReturn([$connectionObj]);
        $this->dbMock->method('deleteRow')->willReturn(true);

        $this->usersMock->method('get')
            ->with('auth0|del456')
            ->willReturn($this->makeResponse(200, ['user_id' => 'auth0|del456']));

        $this->usersMock->expects($this->once())
            ->method('delete')
            ->with('auth0|del456')
            ->willReturn($this->makeResponse(204, null));

        $this->sync->onDeletedUser(999);
    }

    public function testOnDeletedUserSkipsWhenNoConnections(): void
    {
        $this->dbMock->method('getTableName')->willReturn('wp_tob_auth0_accounts');
        $this->dbMock->method('selectResults')->willReturn(null);

        $this->usersMock->expects($this->never())->method('get');
        $this->usersMock->expects($this->never())->method('delete');

        $this->sync->onDeletedUser(888);
    }

    public function testUpdatePasswordSkipsWhenUserNotFound(): void
    {
        $this->usersMock->expects($this->never())->method('get');
        $this->usersMock->expects($this->never())->method('update');

        $this->sync->updatePassword(999999, 'irrelevant');
    }

    public function testUpdatePasswordSyncsToAuth0(): void
    {
        $user = $this->createWpUser(108);

        $connectionObj = (object) ['auth0' => 'auth0|updpwd'];
        $this->dbMock->method('getTableName')->willReturn('wp_tob_auth0_accounts');
        $this->dbMock->method('selectResults')->willReturn([$connectionObj]);

        $this->usersMock->method('get')
            ->willReturn($this->makeResponse(200, ['user_id' => 'auth0|updpwd']));

        $this->usersMock->expects($this->once())
            ->method('update')
            ->with('auth0|updpwd', ['password' => 'Direct123!'])
            ->willReturn($this->makeResponse(200, []));

        $this->sync->updatePassword($user->ID, 'Direct123!');
    }

    // --- Helpers ---

    private function createWpUser(int $seed): WP_User
    {
        $user = $this->createWpUserObject(
            id: $seed,
            login: 'synctest_' . $seed,
            email: 'synctest_' . $seed . '@example.com',
            displayName: 'Sync Test ' . $seed,
            firstName: 'Sync',
            lastName: 'Test' . $seed,
            nickname: 'synctest' . $seed,
        );

        $this->wpUsers[$seed] = $user;

        return $user;
    }

    /**
     * @throws \JsonException
     */
    private function makeResponse(int $statusCode, mixed $body): ResponseInterface&MockObject
    {
        $response = $this->createMock(ResponseInterface::class);
        $response->method('getStatusCode')->willReturn($statusCode);

        $stream = $this->createMock(StreamInterface::class);

        if (null !== $body) {
            $json = json_encode($body, JSON_THROW_ON_ERROR);
            $response->method('getBody')->willReturn($stream);
            $stream->method('__toString')->willReturn($json);
            $stream->method('getContents')->willReturn($json);
        } else {
            $response->method('getBody')->willReturn($stream);
            $stream->method('__toString')->willReturn('');
            $stream->method('getContents')->willReturn('');
        }

        $response->method('getHeaderLine')
            ->willReturnCallback(fn (string $name) => match (strtolower($name)) {
                'content-type' => 'application/json',
                default => '',
            });

        return $response;
    }
}
