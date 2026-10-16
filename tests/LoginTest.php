<?php

declare(strict_types=1);

namespace Empira\Auth\Tests;

use Empira\Application;
use Empira\Auth\Auth;
use Empira\Auth\AuthModule;
use Empira\Auth\LoginPage;
use Empira\Auth\SessionGuard;
use Empira\Auth\User;
use Empira\Auth\UserProvider;
use Empira\Http\Request;
use Empira\Http\Response;
use Empira\Security\Csrf;
use Empira\State\SessionState;
use PHPUnit\Framework\TestCase;

/**
 * The URLs the module publishes, and the journey between them.
 *
 * Driven through a real application rather than by calling the handlers,
 * because what these routes have to get right is mostly *ordering*: the module
 * resolves and registers inside `register()`, the POSTs sit behind a CSRF
 * middleware the application never asked for, and a failure has to re-render
 * the same page rather than a second copy of the form.
 */
final class LoginTest extends TestCase
{
    private const SECRET = 'test-secret-that-is-long-enough-for-hmac!!';

    private const PASSWORD = 'correct horse';

    public function testTheLoginPageIsServedByTheModule(): void
    {
        $app = $this->app();

        $response = $app->handle(new Request('GET', '/login'));

        self::assertSame(200, $response->getStatusCode());
        self::assertStringContainsString('name="email"', $response->body());
        self::assertStringContainsString('name="password"', $response->body());
        self::assertStringContainsString('name="_csrf"', $response->body());
    }

    public function testTheCorrectPasswordRedirectsAndSignsIn(): void
    {
        $app = $this->app();

        $response = $app->handle($this->post('/login', 'ada@example.com', self::PASSWORD));

        self::assertSame(302, $response->getStatusCode());

        $app->handle(new Request('GET', '/who'));

        self::assertSame('7', (string) $app->container()->get(Auth::class)->id());
    }

    /**
     * Both failures produce the same message, and that is the property that
     * matters: the message is the only thing a reader can compare between the
     * two guesses. The email is echoed back in both, which is deliberate — it
     * is how somebody who mistyped it knows what they typed.
     */
    public function testBothFailuresSayTheSameThing(): void
    {
        $app = $this->app();

        $unknown = $app->handle($this->post('/login', 'nobody@example.com', self::PASSWORD));
        $wrong = $app->handle($this->post('/login', 'ada@example.com', 'wrong'));

        self::assertSame(200, $unknown->getStatusCode(), 'a refused sign-in is a page, not a redirect');
        self::assertSame($unknown->getStatusCode(), $wrong->getStatusCode());
        self::assertSame(
            self::errorOf($unknown->body()),
            self::errorOf($wrong->body()),
            'an unknown credential and a wrong password must be indistinguishable',
        );
        self::assertStringContainsString('did not work', self::errorOf($unknown->body()));
    }

    public function testAFailureKeepsTheEmailButNeverThePassword(): void
    {
        $app = $this->app();

        $body = $app->handle($this->post('/login', 'ada@example.com', 'wrong-password'))->body();

        self::assertStringContainsString('ada@example.com', $body, 'mistyping the email is the common case');
        self::assertStringNotContainsString('wrong-password', $body, 'a field that echoes the password has it in the page source');
    }

    public function testThePostIsBehindCsrfEvenThoughTheApplicationNeverAskedForIt(): void
    {
        $app = $this->app();

        // No token: the middleware the module attached for itself refuses.
        $response = $app->handle(new Request(
            'POST',
            '/login',
            body: ['email' => 'ada@example.com', 'password' => self::PASSWORD],
        ));

        self::assertSame(419, $response->getStatusCode());
    }

    public function testLoggingOutForgetsTheUser(): void
    {
        $app = $this->app();

        $app->handle($this->post('/login', 'ada@example.com', self::PASSWORD));

        self::assertSame(302, $app->handle($this->post('/logout'))->getStatusCode());

        $app->handle(new Request('GET', '/who'));

        self::assertNull($app->container()->get(Auth::class)->id());
    }

    /**
     * The seam the whole design turns on: an application that has drawn its own
     * page gets it, and nothing else changes.
     */
    public function testAnApplicationCanReplaceTheLoginPage(): void
    {
        $app = $this->app(ApplicationPage::class);

        $body = $app->handle(new Request('GET', '/login'))->body();

        self::assertStringContainsString('the application draws this', $body);
        self::assertStringNotContainsString('name="email"', $body, 'the module\'s own page was used');
    }

    /**
     * The join: an attribute an application declares reaches the module.
     *
     * Everything else here calls `usePage()` by hand, which proves the setter
     * works and proves nothing about whether `#[LoginPage]` reaches it. That is
     * the same gap the DebugBar toolbar shipped through — a producer, a
     * consumer, and no assertion that the first's output is what the second
     * reads — and it is invisible until an application uses the attribute for
     * real and gets the wrong page.
     *
     * Declared on a subclass of `Application`, because the collection lives in
     * `installModules()` and is protected.
     */
    public function testTheLoginPageAttributeReachesTheModule(): void
    {
        $app = new DeclaredPage();

        $body = $app->handle(new Request('GET', '/login'))->body();


        self::assertStringContainsString('the application draws this', $body);
        self::assertStringNotContainsString(
            'name="email"',
            $body,
            'the module used its own page, so the attribute never reached it'
        );
    }

    /**
     * Declaring nothing is not an error — an absent attribute means "no
     * opinion", and the module falls back to the page it ships.
     */
    public function testAnApplicationDeclaringNoPageGetsTheModulesOwn(): void
    {
        $app = new NoDeclaredPage();

        $body = $app->handle(new Request('GET', '/login'))->body();

        self::assertStringContainsString('name="email"', $body);
    }

    /**
     * A URL the application has already claimed is left alone, rather than
     * fighting for it. The check is by path, because the two pages are different
     * classes with different names — so the application's route has to be in
     * place before the module registers, which is what an application gets when
     * its own route comes from an earlier `discover()`.
     */
    public function testAnApplicationThatAlreadyHasALoginRouteKeepsIt(): void
    {
        $users = $this->users();

        $app = new Application(self::SECRET, new SessionState(), csrf: new Csrf());

        $app->routes()->get('/login', static fn(): Response => Response::html('mine'), 'mine');

        $app->module(new AuthModule([new SessionGuard($app->session(), $users)], $users));

        self::assertSame('mine', $app->handle(new Request('GET', '/login'))->body());
    }

    /**
     * The page's error line, and nothing else.
     *
     * Compared rather than the whole body, because the two pages differ in the
     * email they echo back — which is intended, and which would otherwise hide
     * the one thing that has to match.
     */
    private static function errorOf(string $body): string
    {
        return preg_match('/<p class="error">(.*?)<\/p>/', $body, $m) === 1 ? $m[1] : '';
    }

    // ---------------------------------------------------------------- helpers

    private function post(string $path, string $email = '', string $password = ''): Request
    {
        $app = $this->app();
        $token = $app->csrf()->token();

        return new Request(
            'POST',
            $path,
            body: array_filter(['email' => $email, 'password' => $password, '_csrf' => $token]),
            cookies: ['_csrf_session' => $token],
        );
    }

    private function app(?string $page = null): Application
    {
        $users = $this->users();

        $app = new Application(self::SECRET, new SessionState(), csrf: new Csrf());

        $module = new AuthModule([new SessionGuard($app->session(), $users)], $users);

        if ($page !== null) {
            $module->usePage($page);
        }

        $app->routes()->get('/who', static fn(Auth $auth): Response => Response::html((string) ($auth->id() ?? 'nobody')), 'who');

        $app->module($module);

        return $app;
    }

    private function users(): UserProvider
    {
        return new class(self::PASSWORD) implements UserProvider {
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
    }
}

// ------------------------------------------------------- the attribute, end to end

/**
 * One boot, so the two fixtures below differ only in their attributes.
 *
 * `self::SECRET` cannot reach in from `LoginTest` — a class constant is scoped
 * to its own class and these are separate declarations — which is the same
 * reason an anonymous class cannot inherit one.
 */
abstract class BootingApplication extends Application
{
    private const SECRET = 'test-secret-that-is-long-enough-for-hmac!!';

    public function __construct()
    {
        parent::__construct(self::SECRET, new SessionState(), csrf: new Csrf());
    }
}

/**
 * An application that declares its login page the way a real one would.
 *
 * Extends `Application` rather than using it because `installModules()` is
 * protected — the seam under test is the one a subclass reaches, and a public
 * test double would be testing a different class with the same body.
 */
#[LoginPage(ApplicationPage::class)]
final class DeclaredPage extends BootingApplication
{
    public function __construct()
    {
        parent::__construct();

        $this->installModules([AuthModule::class]);
    }
}

/** The same application with no opinion, which must fall back rather than fail. */
final class NoDeclaredPage extends BootingApplication
{
    public function __construct()
    {
        parent::__construct();

        $this->installModules([AuthModule::class]);
    }
}
