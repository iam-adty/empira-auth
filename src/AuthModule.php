<?php

declare(strict_types=1);

namespace Empira\Auth;

use Doctrine\ORM\EntityManagerInterface;
use Empira\Application;
use Empira\Http\Request;
use Empira\Http\Session;
use Empira\MigrationSource;
use Empira\Module;
use Empira\Security\Guard;

/**
 * Authentication, installed in one call.
 *
 * Everything this package offers, wired together — which is the point of the
 * module existing. Without it an application writes all of it by hand:
 *
 *     $users = new DoctrineUserProvider($app->entities());
 *     $app->orm(self::databaseConfig(), [__DIR__]);     // maps `User`
 *     $app->auth(new SessionGuard($app->session(), $users));
 *
 * With it:
 *
 *     $app->orm(self::databaseConfig(), [__DIR__]);
 *     $app->module(new AuthModule(new DoctrineUserProvider($app->entities())));
 *
 * The entity path is the one thing this module does **not** add for you, and the
 * asymmetry is deliberate: mapping an application's own entities is a decision
 * about that application, while adding the module's is a fact about the module.
 * `orm()` used to hardcode this package's directory, which meant an application
 * could not have an ORM without also getting a `users` table — a framework
 * choosing its application's schema.
 *
 *     $app->orm($config, [...$app->entitiesDeclaredByHand(), AuthModule::entityPath()]);
 *
 * or, if you would rather not think about it, pass `AuthModule::entityPath()`
 * alongside your own directories as you already do.
 */
final class AuthModule implements Module, MigrationSource
{
    /** @var list<Guard> */
    private readonly array $guards;

    /**
     * @param list<Guard>      $guards   consulted in order; a session guard is
     *                                     what makes `login()` possible, so
     *                                     include one
     * @param UserProvider|null $provider the one `Auth::attempt()` checks
     *                                     credentials against; usually the same
     *                                     provider the first guard uses
     * @param Session|null     $session  the application's *own* session, which
     *                                     is what a guard must read — see
     *                                     {@see forApplication()}
     * @param EntityManagerInterface|null $entities the application's entity
     *                                     manager, for building a provider
     */
    public function __construct(
        array $guards = [],
        private readonly ?UserProvider $provider = null,
        ?Session $session = null,
        ?EntityManagerInterface $entities = null,
    ) {
        // An autowired module arrives with **no** guards, and that is not a
        // degraded mode — it is the mode `#[Modules(AuthModule::class)]` puts it
        // in. The container will not complain: `array $guards = []` is a
        // perfectly good default, so the module would register, bind `Auth`, and
        // silently never find a user. Nothing in any log, and a login form that
        // reports "wrong password" forever.
        //
        // So it builds the standard composition itself when it was not given one,
        // from the two services the framework binds before modules register.
        // An explicit list still wins, so nothing that passes guards today
        // changes.
        if ($guards !== []) {
            $this->guards = $guards;

            return;
        }

        $this->guards = $session !== null && $entities !== null
            ? [new SessionGuard($session, new DoctrineUserProvider($entities))]
            : [];
    }

    public function register(Application $app): void
    {
        $app->auth(...$this->guards);

        // The framework binds `RequestUser` per request and knows nothing of a
        // `User`. This binding is what publishes the module's own façade — the
        // object that can narrow to a `User` and can `login()` — so anything
        // type-hinting `Auth` autowires it.
        //
        // Non-shared on purpose (`bind`, not `singleton`), and built from the
        // application rather than captured: the `Request` it holds must be the
        // one for *this* dispatch. A shared instance would be a façade frozen at
        // whichever request first resolved it — the worker trap the framework's
        // own per-request binding exists to avoid.
        $app->container()->bind(Auth::class, function ($container) use ($app): Auth {
            return new Auth($app->guards(), $container->get(Request::class), $this->provider);
        });
    }

    /**
     * The `users` table, in this package's own namespace.
     *
     * The namespace is `Empira\Migrations\Auth` rather than the project's
     * `Empira\Migrations` because Doctrine keys its migration lookup by
     * namespace and this is a different directory. Sharing the namespace would
     * mean two files declaring the same class name, and which one Doctrine ran
     * would depend on which `require` reached the definition first.
     */
    public function migrations(): array
    {
        return ['Empira\\Migrations\\Auth' => dirname(__DIR__) . '/migrations'];
    }

    /**
     * The directory holding this package's `User` entity.
     *
     * Pass it to `orm()` alongside your own directories so the entity is
     * mapped. It is a method rather than a constant because `__DIR__` inside a
     * constant expression is not resolved relative to the consumer.
     */
    public static function entityPath(): string
    {
        return __DIR__;
    }

    /**
     * A guard list built the way most applications want one.
     *
     * Convenience, not policy: it is the composition this package documents, so
     * an application that agrees can skip it and one that does not can pass its
     * own list to the constructor instead.
     */
    public static function guards(SessionGuard $session, ?Guard ...$others): array
    {
        return [$session, ...$others];
    }

    /**
     * Build the standard module for a Doctrine-backed application.
     *
     * The shortest correct wiring, for an application that has already called
     * `orm()`:
     *
     *     $app->orm(self::databaseConfig(), [__DIR__, AuthModule::entityPath()]);
     *     $app->module(AuthModule::forApplication($app));
     *
     * It takes the application rather than an EntityManager because a
     * `SessionGuard` needs the application's *own* session — the same instance
     * the rest of the app writes to, not a fresh one. Building a `Session` here
     * would produce a guard reading a session nothing writes, which is a login
     * form that reports "wrong password" forever.
     */
    public static function forApplication(Application $app, ?Guard ...$others): self
    {
        $users = new DoctrineUserProvider($app->entities());

        return new self(
            self::guards(new SessionGuard($app->session(), $users), ...$others),
            $users,
            $app->session(),
            $app->entities(),
        );
    }
}