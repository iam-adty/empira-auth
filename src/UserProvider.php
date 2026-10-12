<?php

declare(strict_types=1);

namespace Empira\Auth;

/**
 * Where users come from.
 *
 * Separate from {@see Guard} on purpose. A guard answers "who is making *this*
 * request"; a provider answers "which user is that id, and is this password
 * theirs". Keeping them apart is what let a session guard sit on a hand-written
 * provider for years and then sit on the ORM without auth noticing:
 * `DoctrineUserProvider` is interchangeable with any other implementation
 * because both answer this interface and nothing else.
 */
interface UserProvider
{
    /**
     * The user with this id, or null when there is no such user.
     */
    public function byId(int|string $id): ?User;

    /**
     * The user identified by a login, username or email, or null.
     *
     * Only needed when an application signs a user in by something other than
     * a session id.
     */
    public function byCredential(string $credential): ?User;

    /**
     * Is this password this user's?
     *
     * The comparison belongs here rather than in a controller so that the hash
     * never has to leave the layer that stored it.
     */
    public function verifyPassword(User $user, string $password): bool;
}
