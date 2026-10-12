<?php

declare(strict_types=1);

namespace Empira\Auth;

use Empira\Security\RequestUser;

/**
 * Signing in and signing out — the half of authentication that writes.
 *
 * Everything you normally reach for is inherited: `user()`, `check()`,
 * `guest()`, `id()`, `guard()`. Those live in {@see RequestUser}, in the
 * framework, because a layout that prints a name and a CSRF check that asks
 * whether a token proved the request must both work in an application that
 * never installed this module.
 *
 * What is left here is the part that writes a credential, and it cannot be
 * generic. Signing somebody in means giving them a session and rotating its id;
 * signing them out means forgetting it. That is the mechanism's business, so it
 * lives with the mechanism.
 *
 *     $auth->login($user);   // writes
 *     $auth->logout();       // writes
 *
 * An instance is bound per request by {@see \Empira\Application}, so there is
 * nothing to reset and nothing to leak: a fresh instance cannot remember the
 * request before it.
 */
final class Auth extends RequestUser
{
    /**
     * The {@see User} making this request, or null when there is none.
     *
     * Narrows what the parent returns to the type this module knows. Both are
     * the same object — a subclass may only ever promise *more* about a return
     * value, which is why this can be more specific without lying.
     */
    public function user(): ?User
    {
        $user = parent::user();

        return $user instanceof User ? $user : null;
    }

    /**
     * Did a credential the browser will not send on its own prove this request?
     *
     * The name this used to carry — whether a *bearer* token did it — is the
     * bug this no longer has. Naming the mechanism meant CSRF, which lives in
     * the framework, had to know the name of a class in this module, and every
     * future mechanism would have added another `instanceof` line to a file
     * that has no business knowing any of them.
     *
     * @deprecated Ask {@see RequestUser::authenticatedByNonAmbientCredential()}.
     *             The answer is identical and the name outlives the mechanism.
     */
    public function authenticatedByBearer(): bool
    {
        return $this->authenticatedByNonAmbientCredential();
    }

    /**
     * Sign a user in through the first guard that can do it.
     *
     * Only a {@see SessionGuard} can log someone in; a bearer guard validates
     * a credential the client already holds and has nothing to write.
     */
    public function login(User $user): void
    {
        foreach ($this->guards() as $guard) {
            if ($guard instanceof SessionGuard) {
                $guard->login($user);

                $this->resolve($user);

                return;
            }
        }

        throw new \LogicException('No session guard is configured, so there is nowhere to sign a user in.');
    }

    public function logout(): void
    {
        foreach ($this->guards() as $guard) {
            if ($guard instanceof SessionGuard) {
                $guard->logout();
            }
        }

        $this->forget();
    }
}