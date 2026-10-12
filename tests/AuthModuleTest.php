<?php

declare(strict_types=1);

namespace Empira\Auth\Tests;

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
}