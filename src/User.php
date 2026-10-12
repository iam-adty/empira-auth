<?php

declare(strict_types=1);

namespace Empira\Auth;

use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\Mapping as ORM;
use Empira\Security\Identity;

/**
 * Who is making this request — and, since this is the entity the framework
 * persists, who is in the database.
 *
 * It began as a value object on purpose: the framework did not store users, and
 * `UserProvider` was the seam an ORM-backed provider would arrive through
 * without auth noticing. That day has come, and the framework takes the
 * dependency itself. The seam did its job — every guard, every middleware and
 * every component talked to `UserProvider` and never to a row, and that is
 * exactly why swapping the storage underneath was possible.
 *
 * So this is now an entity, and being an entity has consequences worth stating
 * rather than discovering:
 *
 * - **It is managed, not detached.** A `User` that came from a guard belongs to
 *   an `EntityManager`. Reading a lazy association outside the request that
 *   loaded it throws, which is why {@see SessionGuard} stores the *id* and
 *   loads the entity per request rather than holding one.
 * - **It is mutable and identity-mapped.** Ask twice in one request and you get
 *   the same object; ask in the next request and it is loaded again, because the
 *   manager is cleared between them.
 * - **The framework maps the `users` table.** That is a large opinion for a
 *   framework to hold about its users. An application needing other columns
 *   adds them here or maps its own entity behind the same `UserProvider`.
 *
 * The password hash is a column but not a convenience. {@see passwordHash()}
 * exists for the layer that verifies a password, and is deliberately the only
 * way out of it — a component rendering markup has no reason to be able to read
 * one, and an exception carrying an entity cannot accidentally serialise it
 * because the properties are not public.
 *
 *     new User(email: 'ada@example.com', name: 'Ada Lovelace', passwordHash: $hash);
 */
#[ORM\Entity]
#[ORM\Table(name: 'users')]
#[ORM\UniqueConstraint(name: 'users_email_unique', columns: ['email'])]
class User implements Identity
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column(type: Types::INTEGER)]
    private ?int $id = null;

    #[ORM\Column(length: 255)]
    private string $email = '';

    #[ORM\Column(length: 255)]
    private string $name = '';

    #[ORM\Column(name: 'password_hash', length: 255)]
    private string $passwordHash = '';

    /**
     * Whatever the application chose to carry alongside the identity.
     *
     * Kept from the days when a user was a value object and the only way to
     * carry anything extra was a bag. It survives because removing it would be a
     * breaking change for every `attribute('name', '')` in an application, and
     * because an ORM entity and a fixed column set are not the same thing —
     * this is the escape hatch for the columns the framework does not map.
     *
     * @var array<string, mixed>
     */
    #[ORM\Column(type: Types::JSON)]
    private array $attributes = [];

    public function __construct(
        string $email = '',
        string $name = '',
        string $passwordHash = '',
        array $attributes = [],
    ) {
        $this->email = $email;
        $this->name = $name;
        $this->passwordHash = $passwordHash;
        $this->attributes = $attributes;
    }

    /**
     * The identifier, which is null until the entity has been persisted.
     */
    public function id(): ?int
    {
        return $this->id;
    }

    /**
     * Whether this entity has ever been written to the database.
     *
     * Distinct from a null id, which is also what a user being constructed for
     * the first time looks like.
     */
    public function isPersisted(): bool
    {
        return $this->id !== null;
    }

    public function email(): string
    {
        return $this->email;
    }

    public function name(): string
    {
        return $this->name;
    }

    /**
     * The stored hash, for the layer that verifies a password.
     *
     * Public because {@see UserProvider::verifyPassword()} has to reach it from
     * outside, and singular on purpose. Treat a `User` handed to a view as
     * something with no hash in it: this method is the only way out, so a
     * component that never calls it cannot leak one.
     */
    public function passwordHash(): string
    {
        return $this->passwordHash;
    }

    /**
     * Replace the stored hash — for a password change, and nothing else.
     */
    public function changePasswordHash(string $hash): void
    {
        $this->passwordHash = $hash;
    }

    /**
     * One attribute, or a default when it is not there.
     *
     * The identity's own columns answer first, so `$user->attribute('email')`
     * works whether the value came from a column or from the bag.
     */
    public function attribute(string $key, mixed $default = null): mixed
    {
        return match ($key) {
            'id' => $this->id,
            'email' => $this->email,
            'name' => $this->name,
            default => $this->attributes[$key] ?? $default,
        };
    }

    /**
     * @throws \InvalidArgumentException when the attribute is absent
     */
    public function require(string $key): mixed
    {
        if ($key === 'id') {
            return $this->id;
        }

        if (array_key_exists($key, $this->attributes)) {
            return $this->attributes[$key];
        }

        $mapped = match ($key) {
            'email' => $this->email,
            'name' => $this->name,
            default => null,
        };

        if ($mapped === null) {
            throw new \InvalidArgumentException(sprintf('This user has no "%s" attribute.', $key));
        }

        return $mapped;
    }

    /**
     * Put something in the bag, for an application whose columns this class
     * does not map.
     */
    public function withAttribute(string $key, mixed $value): self
    {
        $this->attributes[$key] = $value;

        return $this;
    }

    /**
     * @return array<string, mixed>
     */
    public function attributes(): array
    {
        return $this->attributes;
    }

    public function __toString(): string
    {
        return $this->email;
    }
}