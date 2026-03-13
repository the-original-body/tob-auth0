<?php

declare(strict_types=1);

namespace Tob\Auth0\Actions;

use Auth0\SDK\Exception\ArgumentException;
use Auth0\SDK\Exception\NetworkException;
use Auth0\SDK\Utility\HttpResponse;
use WP_User;

final class UserProfile extends Base
{
    private const string LOG_CHANNEL = "userprofile";

    protected array $registry = [
        'show_user_profile' => 'renderAuth0Section',
        'edit_user_profile' => 'renderAuth0Section',
        'wp_ajax_tob_auth0_verify_email' => 'handleVerifyEmail',
    ];

    public function renderAuth0Section(WP_User $user): void
    {
        if (!current_user_can('edit_users')) {
            return;
        }

        if (!$this->getPlugin()->isReady()) {
            return;
        }

        $auth0User = $this->resolveAuth0User($user);

        if (null === $auth0User) {
            echo '<h2>Auth0</h2>';
            echo '<p>No Auth0 account found for this user.</p>';
            return;
        }

        $emailVerified = $auth0User['email_verified'] ?? false;
        $auth0Email = esc_html($auth0User['email'] ?? '—');

        echo '<h2>Auth0</h2>';
        echo '<table class="form-table"><tbody>';

        echo '<tr>';
        echo '<th>Auth0 Email</th>';
        echo '<td>' . $auth0Email . '</td>';
        echo '</tr>';

        echo '<tr>';
        echo '<th>Email Verified</th>';
        echo '<td>';

        if ($emailVerified) {
            echo '<span style="color:green;font-weight:bold;">&#10003; Verified</span>';
        } else {
            echo '<span id="auth0-verify-email-label" style="color:red;font-weight:bold;">&#10007; Not verified</span>';
            echo '<br><br>';
            echo '<button type="button" class="button" id="auth0-verify-email-btn">Mark Email as Verified</button>';
            echo '<span id="auth0-verify-email-status" style="margin-left:10px;"></span>';

            wp_nonce_field('tob_auth0_verify_email', 'tob_auth0_verify_email_nonce');
            $this->renderVerifyScript($user->ID);
        }

        echo '</td>';
        echo '</tr>';

        echo '</tbody></table>';
    }

    public function handleVerifyEmail(): void
    {
        $this->log(self::LOG_CHANNEL)->debug('handleVerifyEmail: Triggered');

        if (!current_user_can('edit_users')) {
            $this->log(self::LOG_CHANNEL)->warning(
                'handleVerifyEmail: Rejected, insufficient permissions',
                [
                    'current_user_id' => get_current_user_id(),
                ]
            );
            wp_send_json_error('Insufficient permissions.', 403);
        }

        check_ajax_referer('tob_auth0_verify_email');

        $userId = isset($_POST['user_id']) ? (int) $_POST['user_id'] : 0;

        if ($userId <= 0) {
            $this->log(self::LOG_CHANNEL)->error(
                'handleVerifyEmail: Failed, invalid user ID',
                [
                    'user_id' => $userId,
                ]
            );
            wp_send_json_error('Invalid user ID.');
        }

        $user = get_user_by('ID', $userId);

        if (!$user) {
            $this->log(self::LOG_CHANNEL)->error(
                'handleVerifyEmail: Failed, user not found',
                [
                    'user_id' => $userId,
                ]
            );
            wp_send_json_error('User not found.');
        }

        if (!$this->getPlugin()->isReady()) {
            $this->log(self::LOG_CHANNEL)->error('handleVerifyEmail: Failed, plugin not configured');
            wp_send_json_error('Auth0 plugin is not configured.');
        }

        $this->log(self::LOG_CHANNEL)->debug(
            'handleVerifyEmail: Resolving Auth0 user',
            [
                'user_id' => $user->ID,
            ]
        );

        $auth0User = $this->resolveAuth0User($user);

        if (null === $auth0User) {
            $this->log(self::LOG_CHANNEL)->error(
                'handleVerifyEmail: Failed, no Auth0 account found',
                [
                    'user_id' => $user->ID,
                ]
            );
            wp_send_json_error('No Auth0 account found for this user.');
        }

        $connectionId = $auth0User['user_id'] ?? null;

        if (null === $connectionId) {
            $this->log(self::LOG_CHANNEL)->error(
                'handleVerifyEmail: Failed, Auth0 user_id missing in response',
                [
                    'user_id' => $user->ID,
                ]
            );
            wp_send_json_error('Auth0 user_id not found in response.');
        }

        $this->log(self::LOG_CHANNEL)->info(
            'handleVerifyEmail: Setting email_verified=true',
            [
                'user_id' => $user->ID,
                'auth0_id' => $connectionId,
            ]
        );

        $updateResponse = $this->getSdk()->management()->users()->update($connectionId, [
            'email_verified' => true,
        ]);

        if (HttpResponse::wasSuccessful($updateResponse)) {
            $this->log(self::LOG_CHANNEL)->info(
                'handleVerifyEmail: Completed',
                [
                    'user_id' => $user->ID,
                    'auth0_id' => $connectionId,
                ]
            );
            wp_send_json_success();
        }

        $body = $updateResponse->getBody()->getContents();
        $this->log(self::LOG_CHANNEL)->error(
            'handleVerifyEmail: Failed, API error',
            [
                'user_id' => $user->ID,
                'auth0_id' => $connectionId,
                'response' => $body,
            ]
        );
        wp_send_json_error('Auth0 API error: ' . $body);
    }

    /**
     * @throws ArgumentException
     * @throws NetworkException
     * @throws \JsonException
     */
    private function resolveAuth0User(WP_User $user): ?array
    {
        $this->log(self::LOG_CHANNEL)->debug(
            'resolveAuth0User: Looking up Auth0 account',
            [
                'user_id' => $user->ID,
            ]
        );

        $accounts = $this->getPlugin()
            ->getClassInstance(Authentication::class)
            ->accounts();

        $connections = $accounts->getConnections($user->ID);

        if (null !== $connections && [] !== $connections) {
            $this->log(self::LOG_CHANNEL)->debug(
                'resolveAuth0User: Found local connection',
                [
                    'auth0_id' => $connections[0]->auth0,
                ]
            );
            $response = $this->getSdk()->management()->users()->get($connections[0]->auth0);

            if (HttpResponse::wasSuccessful($response)) {
                $this->log(self::LOG_CHANNEL)->debug('resolveAuth0User: Resolved via local connection');
                return HttpResponse::decodeContent($response);
            }

            $this->log(self::LOG_CHANNEL)->warning(
                'resolveAuth0User: Local connection lookup failed, falling back to email search',
                [
                    'auth0_id' => $connections[0]->auth0,
                ]
            );
        }

        // Fallback: search by email
        $this->log(self::LOG_CHANNEL)->debug(
            'resolveAuth0User: Searching by email',
            [
                'user_id' => $user->ID,
            ]
        );
        $response = $this->getSdk()->management()->usersByEmail()->get($user->user_email);

        if (!HttpResponse::wasSuccessful($response)) {
            $this->log(self::LOG_CHANNEL)->warning(
                'resolveAuth0User: Email search failed',
                [
                    'user_id' => $user->ID,
                ]
            );
            return null;
        }

        $results = HttpResponse::decodeContent($response);

        if (!is_array($results) || [] === $results) {
            $this->log(self::LOG_CHANNEL)->info(
                'resolveAuth0User: No Auth0 account found',
                [
                    'user_id' => $user->ID,
                ]
            );
            return null;
        }

        $this->log(self::LOG_CHANNEL)->debug(
            'resolveAuth0User: Resolved via email search',
            [
                'auth0_id' => $results[0]['user_id'] ?? 'unknown',
            ]
        );
        return $results[0];
    }

    private function renderVerifyScript(int $userId): void
    {
        ?>
        <script>
        (function() {
            const btn = document.getElementById('auth0-verify-email-btn');
            const status = document.getElementById('auth0-verify-email-status');

            btn.addEventListener('click', function() {
                if (!confirm('Mark email as verified for this user in Auth0?')) {
                    return;
                }

                btn.disabled = true;
                status.textContent = 'Saving…';
                status.style.color = '';

                const data = new FormData();
                data.append('action', 'tob_auth0_verify_email');
                data.append('user_id', '<?php echo $userId; ?>');
                data.append('_ajax_nonce', document.getElementById('tob_auth0_verify_email_nonce').value);

                fetch(ajaxurl, {
                    method: 'POST',
                    credentials: 'same-origin',
                    body: data
                })
                .then(function(r) { return r.json(); })
                .then(function(resp) {
                    if (resp.success) {
                        const label = document.getElementById('auth0-verify-email-label');
                        label.textContent = '✓ Verified';
                        label.style.color = 'green';
                        btn.remove();
                        status.remove();
                    } else {
                        status.textContent = 'Error: ' + (resp.data || 'Unknown error');
                        status.style.color = 'red';
                        btn.disabled = false;
                    }
                })
                .catch(function() {
                    status.textContent = 'Request failed.';
                    status.style.color = 'red';
                    btn.disabled = false;
                });
            });
        })();
        </script>
        <?php
    }
}
