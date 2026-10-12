<?php

declare(strict_types=1);

namespace Empira\Auth;

use Doctrine\ORM\EntityManagerInterface;

/**
 * A {@see UserProvider} backed by the ORM.
 *
 * This is what {@see User} being an entity was for. The guard above still only
 * knows this interface, which is why swapping the storage underneath left every
 * guard, every middleware and every component untouched — `docs/auth.md` called
 * `UserProvider` the ORM seam years before there was an ORM to point it at.
 *
 * The hash is verified here and nowhere else, exactly as it was when the
 * provider read rows: a controller is handed a `User` and never the string that
 * was compared against.
 *
 * One thing about the manager is worth stating, because it is the trap that
 * costs a day under a worker. A provider holds an `EntityManagerInterface` for
 * as long as the guard does — that is, for the life of the process. What keeps
 * that safe is not anything in this class; it is {@see \Empira\Application}
 * clearing the manager between requests. A provider that found a manager that
 * had *not* been cleared would hand back the previous request's user.
 */
final class DoctrineUserProvider implements UserProvider
{
    public function __construct(private readonly EntityManagerInterface $entities)
    {
    }

    public function byId(int|string $id): ?User
    {
        if (!is_numeric($id)) {
            return null;
        }

        return $this->entities->find(User::class, (int) $id);
    }

    public function byCredential(string $credential): ?User
    {
        return $this->entities->getRepository(User::class)->findOneBy(['email' => $credential]);
    }

    public function verifyPassword(User $user, string $password): bool
    {
        $hash = $user->passwordHash();

        // A user with no stored hash cannot be authenticated, and saying so
        // with false is what stops a missing column reading as "any password
        // works". The entity always has a string, so this is about a provider
        // handed something that never came from the database.
        if ($hash === '') {
            return false;
        }

        return password_verify($password, $hash);
    }

    /**
     * Hash a password for storage.
     *
     * On the provider rather than on the entity so that constructing a `User`
     * never silently does a bcrypt — entities are loaded, constructed and
     * compared constantly, and most of those comparisons want no hashing at all.
     */
    public function hash(string $password): string
    {
        return password_hash($password, PASSWORD_DEFAULT);
    }
}