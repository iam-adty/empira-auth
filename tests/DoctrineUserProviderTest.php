<?php

declare(strict_types=1);

namespace Empira\Auth\Tests;

use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\Tools\SchemaTool;
use Empira\Auth\DoctrineUserProvider;
use Empira\Auth\User;
use Empira\Config\Config;
use Empira\Persistence\EntityManagerFactory;
use PHPUnit\Framework\TestCase;

/**
 * The ORM-backed {@see \Empira\Auth\UserProvider}.
 *
 * These replace a set of tests that covered `DatabaseUserProvider`, which read
 * rows by hand. The assertions are deliberately the same four — find by id,
 * find by credential, verify a password, refuse a missing hash — because those
 * were the behaviours worth having covered, and the storage under them changed.
 */
final class DoctrineUserProviderTest extends TestCase
{
    /**
     * bcrypt hashes, computed once and pasted.
     *
     * `password_hash()` costs about half a second at the default cost, and this
     * class builds its fixture seven times. The hashes are still real bcrypt —
     * `verifyPassword()` uses `password_verify()`, which is the thing under test
     * — so nothing is stubbed; only the arithmetic is skipped.
     */
    private const HASH_CORRECT = '$2y$10$Ua89QG/6trEgtY0K1UKd2Ot6.giI.2..iM8F1dZqqW8K9/c/IDEma';
    private const HASH_ROTATED = '$2y$10$fGb0zIDDuq91M06ES6dbH.aENpo5IL3SXSFsCEzoA5.tHzPa5Gnhe';

    private EntityManagerInterface $entities;

    private DoctrineUserProvider $users;

    protected function setUp(): void
    {
        $this->entities = EntityManagerFactory::make(
            new Config(['driver' => 'sqlite', 'database' => ':memory:']),
            [__DIR__ . '/../src'],
        );

        // The schema comes from the mapping rather than from SQL, which is also
        // a check in itself: if `User` and a hand-written migration ever disagree
        // about a column, these fixtures stop matching what a deployed database
        // looks like.
        (new SchemaTool($this->entities))->createSchema(
            [$this->entities->getClassMetadata(User::class)]
        );

        $this->users = new DoctrineUserProvider($this->entities);

        $this->entities->persist(new User('ada@example.com', 'Ada', self::HASH_CORRECT));

        // Deliberately has no hash at all.
        $this->entities->persist(new User('ghost@example.com', 'Ghost', ''));

        $this->entities->flush();
        $this->entities->clear();
    }

    public function testItFindsUsersByIdAndCredential(): void
    {
        self::assertSame('Ada', $this->users->byId(1)?->attribute('name'));
        self::assertSame('Ada', $this->users->byCredential('ada@example.com')?->attribute('name'));
        self::assertNull($this->users->byId(99));
        self::assertNull($this->users->byCredential('nobody@example.com'));
    }

    public function testANonNumericIdIsRefusedRatherThanCoerced(): void
    {
        // The interface allows int|string. A string that is not a number is not
        // a user, and passing it to a typed `find()` would be a TypeError deep
        // inside Doctrine rather than a null here.
        self::assertNull($this->users->byId('not-an-id'));
    }

    public function testThePasswordHashIsNotInTheAttributesBag(): void
    {
        $user = $this->users->byId(1);

        self::assertNotNull($user);
        self::assertArrayNotHasKey('password_hash', $user->attributes());
        self::assertSame('ada@example.com', $user->attribute('email'));

        // …and it is not reachable by guessing a key either, even though the
        // column exists and `passwordHash()` will hand it over on purpose.
        self::assertNull($user->attribute('password_hash'));
    }

    public function testItVerifiesPasswords(): void
    {
        $ada = $this->users->byId(1);

        self::assertNotNull($ada);
        self::assertTrue($this->users->verifyPassword($ada, 'correct horse'));
        self::assertFalse($this->users->verifyPassword($ada, 'wrong horse'));
        self::assertFalse($this->users->verifyPassword($ada, ''));
    }

    public function testAUserWithNoStoredHashCannotBeAuthenticated(): void
    {
        $ghost = $this->users->byId(2);

        self::assertNotNull($ghost);
        self::assertFalse(
            $this->users->verifyPassword($ghost, 'anything'),
            'a missing hash is not a wildcard'
        );
    }

    public function testTheSameRequestGetsTheSameInstanceBack(): void
    {
        // What makes `User` an entity rather than a value object: ask twice in
        // one request and the identity map hands back the *same* object rather
        // than two equal ones.
        $first = $this->users->byId(1);
        $second = $this->users->byId(1);

        self::assertSame($first, $second);
    }

    public function testClearingTheManagerForcesAFreshRead(): void
    {
        // This is what `Application::handle()` does at the start of every
        // request, and it is the only reason a worker may hold one manager for
        // the life of the process.
        $stale = $this->users->byId(1);

        self::assertNotNull($stale);
        self::assertTrue($this->users->verifyPassword($stale, 'correct horse'));

        // Changed behind the manager's back — a second process, a psql session,
        // an admin tool. The identity map does not know, and the cached entity
        // is now a lie.
        $this->entities->getConnection()->executeStatement(
            'UPDATE users SET password_hash = ? WHERE email = ?',
            [self::HASH_ROTATED, 'ada@example.com'],
        );

        // Still the old answer. Under php-fpm that is invisible, because the
        // process ends with the request; under a worker it is request two being
        // served request one's user, silently.
        self::assertTrue(
            $this->users->verifyPassword($this->users->byId(1), 'correct horse'),
            'before the reset the identity map serves the cached entity'
        );

        $this->entities->clear();

        self::assertFalse(
            $this->users->verifyPassword($this->users->byId(1), 'correct horse'),
            'a cleared manager must read through to the database'
        );

        self::assertTrue(
            $this->users->verifyPassword($this->users->byId(1), 'rotated elsewhere')
        );
    }
}