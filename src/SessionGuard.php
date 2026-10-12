<?php

declare(strict_types=1);

namespace Empira\Auth;

use Empira\Http\Request;
use Empira\Http\Session;
use Empira\Http\SessionId;

/**
 * Signs a user in with the session.
 *
 * The session cookie is an *ambient* credential: the browser attaches it to
 * every request to this site without being asked. That is what makes a session
 * convenient and what makes CSRF protection necessary, and it is why this
 * guard is the one {@see \Empira\Http\Middleware\VerifyCsrfToken} will
 * not exempt.
 *
 *     $app->auth(new SessionGuard($session, $users));
 *
 *     $guard->login($user);   // rotates the session id, then stores the id
 *     $guard->logout();        // forgets it
 */
final class SessionGuard implements Guard
{
    public const DEFAULT_KEY = 'user_id';

    public function __construct(
        private readonly Session $session,
        private readonly UserProvider $users,
        private readonly string $key = self::DEFAULT_KEY,
        private readonly ?SessionId $rotator = null,
    ) {
    }

    public function identify(Request $request): ?User
    {
        $id = $this->session->get($this->key);

        if ($id === null) {
            return null;
        }

        return $this->users->byId($id);
    }

    /**
     * Sign a user in.
     *
     * The session id is regenerated first. If it were not, an attacker who
     * could set a cookie in someone's browser before they signed in would be
     * holding that same id afterwards — session fixation, and the reason
     * `regenerate()` exists on {@see Session}.
     */
    public function login(User $user): void
    {
        ($this->rotator ?? $this->session)->regenerate();

        $this->session->put($this->key, $user->id());
    }

    public function logout(): void
    {
        $this->session->forget($this->key);
    }
}
