<?php

declare(strict_types=1);

namespace Empira\Auth\Tests;

use Empira\Auth\Auth;
use Empira\Auth\BearerGuard;
use Empira\Auth\Guard;
use Empira\Auth\Middleware\RequireAuth;
use Empira\Auth\AuthModule;
use Empira\Auth\SessionGuard;
use Empira\Auth\User;
use Empira\Auth\UserProvider;
use Empira\Application;
use Empira\Http\Middleware\VerifyCsrfToken;
use Empira\Http\Request;
use Empira\Http\Response;
use PHPUnit\Framework\TestCase;

/**
 * Who is asking, and what that changes about the request.
 */
final class AuthTest extends TestCase
{
    private const SECRET = 'a-secret-that-is-long-enough';

    protected function setUp(): void
    {
        $_SESSION = [];
    }

    /**
     * An application with the module installed but no guards yet.
     *
     * Installing the module is how this package is actually used, and it is what
     * binds `Auth` — the framework binds only its own `RequestUser`. A test that
     * reached for `Auth` from the container without installing the module was
     * relying on wiring that no longer exists (and should not).
     */
    private function app(): Application
    {
        $app = new Application(self::SECRET, new \Empira\State\NullState());
        $app->module(new AuthModule());

        return $app;
    }

    /**
     * A user that looks as though it came out of the database.
     *
     * `User` is an entity now, and its id is private and assigned by the ORM on
     * flush. These tests are about auth — who is asking, what the guard returns,
     * what lands in the session — and none of them is about persistence, so
     * rather than flush an entity per test the id is set directly.
     *
     * Reflection, deliberately: a public `setId()` would be a way to claim an
     * identity that was never issued, and it would exist only for these tests.
     */
    public static function persisted(int $id, string $email = 'ada@example.com', string $name = 'Ada'): User
    {
        $user = new User($email, $name);

        (new \ReflectionProperty(User::class, 'id'))->setValue($user, $id);

        return $user;
    }

    private function request(string $method = 'GET', string $path = '/', array $headers = []): Request
    {
        return new Request($method, $path, headers: $headers);
    }

    // ------------------------------------------------------------- guards

    public function testABearerGuardReadsTheAuthorizationHeader(): void
    {
        $ada = self::persisted(1, 'ada@example.com', 'Ada');
        $guard = new BearerGuard(fn(string $token): ?User => $token === 'secret' ? $ada : null);

        $this->assertSame($ada, $guard->identify($this->request(headers: ['authorization' => 'Bearer secret'])));
    }

    public function testTheBearerSchemeIsCaseInsensitive(): void
    {
        // RFC 7235 defines the scheme case-insensitively and clients send it
        // however they like.
        $guard = new BearerGuard(fn(string $t): ?User => $t === 'secret' ? self::persisted(1) : null);

        $this->assertNotNull($guard->identify($this->request(headers: ['authorization' => 'bearer secret'])));
        $this->assertNotNull($guard->identify($this->request(headers: ['authorization' => 'BEARER secret'])));
    }

    public function testABearerGuardIgnoresAnythingThatIsNotItsScheme(): void
    {
        $guard = new BearerGuard(fn(string $t): ?User => self::persisted(1));

        $this->assertNull($guard->identify($this->request(headers: ['authorization' => 'Basic c3RhbGU6'])));
        $this->assertNull($guard->identify($this->request(headers: ['authorization' => 'Bearer'])));
        $this->assertNull($guard->identify($this->request(headers: ['authorization' => 'Bearer    '])));
        $this->assertNull($guard->identify($this->request()));
    }

    public function testABearerGuardReturnsNullForATokenItDoesNotKnow(): void
    {
        // Returning a user for an unrecognised credential would be a way to
        // authenticate anyone.
        $guard = new BearerGuard(fn(string $t): ?User => null);

        $this->assertNull($guard->identify($this->request(headers: ['authorization' => 'Bearer nope'])));
    }

    public function testAnUnrecognisedTokenIsNotTheSameAsNoHeader(): void
    {
        $app = $this->app();
        $guard = new BearerGuard(fn(string $t): ?User => null);
        $auth = new Auth([$guard], $this->request(headers: ['authorization' => 'Bearer wrong']));

        $this->assertTrue($auth->guest(), 'a wrong token is not a signed-in user');
    }

    // ------------------------------------------------------------- Auth

    public function testAuthResolvesTheFirstGuardThatAnswers(): void
    {
        $ada = self::persisted(1);
        $auth = new Auth([
            new BearerGuard(fn(string $t): ?User => $t === 'bearer' ? self::persisted(2) : null),
            new BearerGuard(fn(string $t): ?User => $t === 'bearer' ? $ada : null),
        ], $this->request(headers: ['authorization' => 'Bearer bearer']));

        $this->assertSame(2, $auth->id());
    }

    public function testAuthAsksItsGuardsOnlyOnce(): void
    {
        // A page that asks in a layout and again in a controller should not run
        // the guards twice; some of them hash or hit a session file.
        $calls = 0;
        $guard = new class ($calls) implements Guard {
            public function __construct(private int &$calls) {}

            public function identify(Request $request): ?User
            {
                $this->calls++;

                return AuthTest::persisted(1);
            }
        };

        $auth = new Auth([$guard], $this->request());
        $auth->user();
        $auth->user();
        $auth->check();

        $this->assertSame(1, $calls);
    }

    public function testAuthWithoutARequestFindsNobody(): void
    {
        // A console command has no request, and must not be handed a user.
        $auth = new Auth([new BearerGuard(fn(string $t): ?User => self::persisted(1))]);

        $this->assertTrue($auth->guest());
    }

    public function testAuthRemembersWhichGuardAnswered(): void
    {
        $auth = new Auth([
            new BearerGuard(fn(string $t): ?User => self::persisted(9)),
        ], $this->request(headers: ['authorization' => 'Bearer x']));

        $this->assertInstanceOf(BearerGuard::class, $auth->guard());
        $this->assertTrue($auth->authenticatedByBearer());
    }

    // ------------------------------------------------------ RequireAuth

    public function testRequireAuthRefusesAnAnonymousRequest(): void
    {
        $app = $this->app();
        $app->routes()->get('/secret', static fn(): string => 'shh', 'secret');
        $app->use(RequireAuth::class);

        $this->assertSame(401, $app->handle($this->request(path: '/secret'))->status());
    }

    public function testRequireAuthLetsAnIdentifiedRequestThrough(): void
    {
        $app = $this->app();
        $app->routes()->get('/secret', static fn(): string => 'shh', 'secret');
        $app->auth(new BearerGuard(fn(string $t): ?User => self::persisted(1)));
        $app->use(RequireAuth::class);

        $response = $app->handle($this->request(headers: ['authorization' => 'Bearer x'], path: '/secret'));

        $this->assertSame(200, $response->status());
        $this->assertSame('shh', $response->body());
    }

    public function testRequireAuthRefusesInTheNegotiatedFormat(): void
    {
        // The point of throwing rather than returning: a JSON client gets the
        // same envelope every other failure uses, without this class knowing
        // what that envelope looks like.
        $app = $this->app();
        $app->routes()->get('/secret', static fn(): string => 'shh', 'secret');
        $app->use(RequireAuth::class);

        $response = $app->handle($this->request(headers: ['accept' => 'application/json']));

        $this->assertSame(401, $response->status());
        $this->assertStringContainsString('"error"', $response->body());
    }

    public function testRequireAuthWithoutAnyAuthConfiguredRefuses(): void
    {
        // Fail closed: a middleware with no guards must not wave requests through.
        $app = $this->app();
        $app->routes()->get('/secret', static fn(): string => 'shh', 'secret');
        $app->use(new RequireAuth());

        $this->assertSame(401, $app->handle($this->request(path: '/secret'))->status());
    }

    public function testAuthIsBoundFreshForEveryRequest(): void
    {
        // The reason Auth is per-request: an Application outlives a request, and
        // a user resolved for one must not be visible to the next.
        $app = $this->app();
        $app->routes()->get('/who', static function (Auth $auth): Response {
            return Response::html((string) ($auth->id() ?? 'nobody'));
        }, 'who');
        $app->auth(new BearerGuard(fn(string $t): ?User => $t === 'ada' ? self::persisted(1) : null));

        $first = $app->handle($this->request(headers: ['authorization' => 'Bearer ada'], path: '/who'));
        $second = $app->handle($this->request(path: '/who'));

        $this->assertSame('1', $first->body());
        $this->assertSame('nobody', $second->body(), 'identity must not survive the request');
    }

    public function testASessionUserIsCarriedAcrossRequestsButNotBeyondItsOwn(): void
    {
        $app = $this->app();
        $app->auth(new SessionGuard($app->session(), $this->users()));
        $app->routes()->get('/who', static fn(Auth $auth): Response => Response::html((string) ($auth->id() ?? 'nobody')), 'who');

        $this->assertSame('nobody', $app->handle($this->request(path: '/who'))->body());

        // Auth is bound per request, so signing in means asking the instance
        // this request produced.
        $app->handle($this->request(path: '/who'));
        $app->container()->get(Auth::class)->login(self::persisted(7, 'ada@example.com', 'Ada'));

        $this->assertSame('7', $app->handle($this->request(path: '/who'))->body());
    }

    public function testLogoutForgetsTheUser(): void
    {
        $app = $this->app();
        $app->auth(new SessionGuard($app->session(), $this->users()));
        $app->routes()->get('/who', static fn(Auth $auth): Response => Response::html((string) ($auth->id() ?? 'nobody')), 'who');

        $app->handle($this->request(path: '/who'));
        $app->container()->get(Auth::class)->login(self::persisted(7));
        $this->assertSame('7', $app->handle($this->request(path: '/who'))->body());

        $app->container()->get(Auth::class)->logout();
        $this->assertSame('nobody', $app->handle($this->request(path: '/who'))->body());
    }

    public function testLoggingInRotatesTheSessionId(): void
    {
        // Session::regenerate() is a no-op under the CLI, so watching the id
        // change would prove nothing. This asserts the rotation is *asked for*,
        // which is the part under our control and the part that would otherwise
        // go untested.
        $rotator = new class implements \Empira\Http\SessionId {
            public int $rotated = 0;

            public function regenerate(): void
            {
                $this->rotated++;
            }
        };

        $session = new \Empira\Http\Session('auth-test', false);
        $guard = new SessionGuard($session, $this->users(), rotator: $rotator);

        $this->assertSame(0, $rotator->rotated);

        $guard->login(self::persisted(7));

        $this->assertSame(1, $rotator->rotated, 'login must rotate, or the id is fixated');
        $this->assertSame(7, $session->get('user_id'));
    }

    public function testLoggingInWithoutASessionGuardSaysSo(): void
    {
        $auth = new Auth([new BearerGuard(fn(string $t): ?User => self::persisted(1))]);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('No session guard');

        $auth->login(self::persisted(1));
    }

    // ---------------------------------------------------------------- CSRF

    public function testABearerAuthenticatedPostIsExemptFromCsrf(): void
    {
        $app = $this->guardedApp(new BearerGuard(fn(string $t): ?User => self::persisted(1)));

        $response = $app->handle($this->request('POST', '/api', ['authorization' => 'Bearer x']));

        $this->assertSame(200, $response->status(), 'no CSRF token, but not forgeable either');
    }

    public function testASessionAuthenticatedPostWithoutATokenIsStillRefused(): void
    {
        // This is the attack. "There is a user" is not the question — an
        // ambient cookie is exactly what CSRF exists to defend, so a
        // session-authenticated POST with no token has to stay refused.
        $app = $this->app();
        $app->csrf(new \Empira\Security\Csrf());
        $app->routes()->post('/api', static fn(): string => 'ok', 'api');
        $app->auth(new SessionGuard($app->session(), $this->users()));
        $app->use(VerifyCsrfToken::class);

        // Sign in on one request…
        $app->handle($this->request());
        $app->container()->get(Auth::class)->login(self::persisted(7));

        // …then post with no token on the next.
        $this->assertSame(419, $app->handle($this->request('POST', '/api'))->status());
    }

    public function testARouteCanOptOutOfCsrfEntirely(): void
    {
        $app = $this->app();
        $app->routes()->post('/webhook', static fn(): string => 'ok', 'webhook', csrf: false);
        $app->use(VerifyCsrfToken::class);

        $this->assertSame(200, $app->handle($this->request('POST', '/webhook'))->status());
    }

    public function testARouteThatDidNotOptOutIsStillChecked(): void
    {
        $app = $this->app();
        $app->routes()->post('/ordinary', static fn(): string => 'ok', 'ordinary');
        $app->use(VerifyCsrfToken::class);

        $this->assertSame(419, $app->handle($this->request('POST', '/ordinary'))->status());
    }

    // ----------------------------------------------------------- helpers

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

    private function guardedApp(Guard $guard): Application
    {
        $app = $this->app();
        $app->csrf(new \Empira\Security\Csrf());
        $app->routes()->post('/api', static fn(): string => 'ok', 'api');
        $app->auth($guard);
        $app->use(VerifyCsrfToken::class);

        return $app;
    }
}
