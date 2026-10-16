<?php

declare(strict_types=1);

namespace Empira\Auth\Tests;

use Doctrine\ORM\EntityManagerInterface;
use Empira\Application;
use Empira\Auth\Auth;
use Empira\Auth\AuthModule;
use Empira\Auth\SessionGuard;
use Empira\Auth\User;
use Empira\Auth\UserProvider;
use Empira\Http\Request;
use Empira\Http\Response;
use Empira\Security\RequestUser;
use Empira\State\NullState;
use Empira\State\SessionState;
use PHPUnit\Framework\TestCase;

/**
 * The module — how this package is actually installed.
 *
 * Every other test here builds an application by hand. These check the wiring a
 * real application uses, which is the part that can rot without any of them
 * noticing: the framework binds only its own `RequestUser`, and the module's
 * `Auth` binding is the only reason `Auth` resolves at all.
 */
final class AuthModuleTest extends TestCase
{
    private const SECRET = 'test-secret-that-is-long-enough-for-hmac!!';

    public function testInstallingTheModuleRegistersItsGuards(): void
    {
        $app = new Application(self::SECRET, new NullState());
        $app->module(new AuthModule([new SessionGuard($app->session(), $this->users())]));

        self::assertCount(1, $app->guards());
        self::assertCount(1, $app->modules());
        self::assertInstanceOf(AuthModule::class, $app->modules()[0]);
    }

    public function testInstallingTheModulePublishesTheAuthFacade(): void
    {
        $app = $this->app();
        $app->handle(new Request('GET', '/who'));

        self::assertInstanceOf(Auth::class, $app->container()->get(Auth::class));
    }

    /**
     * The two bindings are separate objects, and that is not tidiness — see the
     * trap in AGENTS.md. `Auth` narrows `user()` to `User`, so one object
     * serving both contracts would report any other `Identity` as nobody.
     */
    public function testTheFrameworkBindsItsOwnContextAndTheModuleBindsItsOwn(): void
    {
        $app = $this->app();
        $app->handle(new Request('GET', '/who'));

        $container = $app->container();

        self::assertInstanceOf(RequestUser::class, $container->get(RequestUser::class));
        self::assertInstanceOf(Auth::class, $container->get(Auth::class));
    }

    /**
     * `Auth` is per request, like everything else that holds one. A shared
     * instance would be a façade frozen at whichever request resolved it first,
     * which under a worker means request two served as request one.
     */
    public function testTheFacadeIsRebuiltForEveryRequest(): void
    {
        $app = $this->app();

        $app->handle(new Request('GET', '/who'));
        $first = $app->container()->get(Auth::class);

        $app->handle(new Request('GET', '/who'));
        $second = $app->container()->get(Auth::class);

        self::assertNotSame($first, $second);
    }

    public function testTheFacadeAnswersForTheSameGuardsTheFrameworkResolvesFrom(): void
    {
        $app = $this->app();
        $app->routes()->get('/who', static fn(Auth $auth): Response => Response::html((string) ($auth->id() ?? 'nobody')), 'who');

        self::assertSame('nobody', $app->handle(new Request('GET', '/who'))->body());

        $app->handle(new Request('GET', '/who'));
        $app->container()->get(Auth::class)->login(AuthTest::persisted(7));

        // If the façade were built from a different guard list, this would still
        // say 'nobody' — and only this test would say so.
        self::assertSame('7', $app->handle(new Request('GET', '/who'))->body());
    }

    /**
     * The `users` table ships with this package, so an application that installs
     * auth gets its schema without writing a migration.
     */
    /**
     * The module built by the container, with nothing passed.
     *
     * `#[Modules(AuthModule::class)]` resolves the class and lets the container
     * construct it, so this is the construction that path uses — and the one
     * that used to produce a module with **no guards at all**, silently.
     */
    public function testAnAutowiredModuleBuildsItsOwnSessionGuard(): void
    {
        $app = new Application(self::SECRET, new SessionState());
        $app->container()->instance(EntityManagerInterface::class, $this->entities());

        $guards = self::guardsOf($app->container()->get(AuthModule::class));

        self::assertCount(1, $guards, 'an autowired module must not be left without guards');
        self::assertInstanceOf(SessionGuard::class, $guards[0]);
    }

    /**
     * With no entity manager bound there is no provider to build one from, and
     * the module says so with no guards rather than inventing a half-working one.
     * An application that calls `orm()` after registering modules gets the
     * dependency; one that never does has no users to authenticate.
     */
    public function testAnAutowiredModuleWithNoEntityManagerHasNoGuards(): void
    {
        $app = new Application(self::SECRET, new SessionState());

        self::assertSame([], self::guardsOf($app->container()->get(AuthModule::class)));
    }

    public function testExplicitGuardsStillWinOverTheBuiltInComposition(): void
    {
        $app = new Application(self::SECRET, new SessionState());
        $guard = new SessionGuard($app->session(), $this->users());
        $module = new AuthModule([$guard]);

        self::assertSame([$guard], self::guardsOf($module));
    }

    public function testAnAutowiredModuleWorksAfterTheApplicationHasCalledOrm(): void
    {
        $app = new Application(self::SECRET, new SessionState());
        $app->orm(['driver' => 'sqlite', 'database' => ':memory:'], [AuthModule::entityPath()]);

        // The ordering an attribute-driven application uses: `orm()` first, so
        // the entity manager exists, then the module resolved by class name. This
        // is the whole reason self-sufficiency was worth doing.
        $guards = self::guardsOf($app->container()->get(AuthModule::class));

        self::assertCount(1, $guards);
        self::assertInstanceOf(SessionGuard::class, $guards[0]);
    }

    /**
     * `attempt()` is the primitive a login page needs and the reason `Auth` was
     * given a provider: the module could verify a password but nothing could ask
     * it to.
     */
    public function testAttemptSignsInTheRightPasswordAndRefusesTheWrongOne(): void
    {
        $app = $this->appWithProvider('correct horse');
        $app->handle(new Request('GET', '/who'));

        $auth = $app->container()->get(Auth::class);

        self::assertNull($auth->attempt('nobody@example.com', 'correct horse'), 'no such user must refuse');
        self::assertNull($auth->attempt('ada@example.com', 'wrong'), 'the wrong password must refuse');
        self::assertSame(7, $auth->attempt('ada@example.com', 'correct horse')?->id(), 'the right password must sign in');
    }

    public function testAttemptRefusesWhenNoProviderIsConfigured(): void
    {
        $app = $this->app();
        $app->handle(new Request('GET', '/who'));

        // Not an exception: a caller asking a question gets an answer, and the
        // answer a login form can act on is "that did not work".
        self::assertNull($app->container()->get(Auth::class)->attempt('ada@example.com', 'anything'));
    }

    public function testTheModuleContributesItsMigrations(): void
    {
        $module = new AuthModule();
        $sources = $module->migrations();

        self::assertArrayHasKey('Empira\\Migrations\\Auth', $sources);
        self::assertDirectoryExists($sources['Empira\\Migrations\\Auth']);
        self::assertFileExists($sources['Empira\\Migrations\\Auth'] . '/Version20261011000001.php');
    }

    /**
     * The namespace must match what the migration files declare. Doctrine keys
     * its lookup by namespace, so a mismatch means the file is found, read, and
     * discarded — `migrate` says "Nothing to migrate" with no error anywhere.
     */
    public function testTheMigrationNamespaceMatchesTheFilesThatDeclareIt(): void
    {
        $module = new AuthModule();

        foreach ($module->migrations() as $namespace => $directory) {
            foreach (glob($directory . '/Version*.php') ?: [] as $file) {
                $declared = null;

                foreach (file($file) ?: [] as $line) {
                    if (preg_match('/^namespace\s+(.+?);/', $line, $m) === 1) {
                        $declared = trim($m[1]);

                        break;
                    }
                }

                self::assertSame($namespace, $declared, basename($file) . ' declares a different namespace than the module advertises');
            }
        }
    }

    public function testTheEntityPathPointsAtThisPackagesUser(): void
    {
        self::assertFileExists(AuthModule::entityPath() . '/User.php');
    }

    /**
     * The guard is built from the *application's* session, which is the only
     * one anything else writes to. A guard given a session of its own would read
     * a store nobody writes, and every sign-in would fail as a wrong password.
     */
    private function app(): Application
    {
        $app = new Application(self::SECRET, new NullState());
        $app->module(new AuthModule([new SessionGuard($app->session(), $this->users())]));

        return $app;
    }

    private function users(): UserProvider
    {
        return new class implements UserProvider {
            public function byId(int|string $id): ?User
            {
                return (string) $id === '7' ? AuthTest::persisted(7, 'ada@example.com', 'Ada') : null;
            }

            public function byCredential(string $credential): ?User
            {
                return null;
            }

            public function verifyPassword(User $user, string $password): bool
            {
                return false;
            }
        };
    }

    /**
     * @return list<\Empira\Security\Guard>
     */
    private static function guardsOf(AuthModule $module): array
    {
        return (new \ReflectionProperty(AuthModule::class, 'guards'))->getValue($module);
    }

    private function entities(): EntityManagerInterface
    {
        return $this->createMock(EntityManagerInterface::class);
    }

    /**
     * An application whose provider accepts exactly one password.
     */
    private function appWithProvider(string $password): Application
    {
        $users = new class($password) implements UserProvider {
            public function __construct(private readonly string $password)
            {
            }

            public function byId(int|string $id): ?User
            {
                return (string) $id === '7' ? AuthTest::persisted(7, 'ada@example.com', 'Ada') : null;
            }

            public function byCredential(string $credential): ?User
            {
                return $credential === 'ada@example.com' ? AuthTest::persisted(7, 'ada@example.com', 'Ada') : null;
            }

            public function verifyPassword(User $user, string $password): bool
            {
                return $password === $this->password;
            }
        };

        $app = new Application(self::SECRET, new SessionState());

        $app->module(new AuthModule([new SessionGuard($app->session(), $users)], $users));

        return $app;
    }
}