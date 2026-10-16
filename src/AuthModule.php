<?php

declare(strict_types=1);

namespace Empira\Auth;

use Doctrine\ORM\EntityManagerInterface;
use Empira\Application;
use Empira\Auth\Pages\LoginLayout;
use Empira\ConfigurableModule;
use Empira\Http\Middleware\VerifyCsrfToken;
use Empira\Http\Request;
use Empira\Http\Response;
use Empira\Http\Session;
use Empira\MigrationSource;
use Empira\Routing\RouteCollection;
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
final class AuthModule implements ConfigurableModule, MigrationSource
{
    public const LOGIN_PATH = '/login';

    public const LOGOUT_PATH = '/logout';

    /** @var list<Guard> */
    private readonly array $guards;

    /** The page `GET /login` renders. */
    private ?string $loginPage = LoginLayout::class;

    /** Where to send somebody once they are signed in, or out. */
    private string $redirectAfterLogin = '/';

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
     * @param class-string|null $loginPage the layout `GET /login` renders
     */
    public function __construct(
        array $guards = [],
        private readonly ?UserProvider $provider = null,
        ?Session $session = null,
        ?EntityManagerInterface $entities = null,
        ?string $loginPage = null,
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

        if ($loginPage !== null) {
            $this->loginPage = $loginPage;
        }
    }

    /**
     * The page `GET /login` renders.
     *
     * An application almost always wants its own, because this package cannot
     * know what the rest of its pages look like — a layout is the application's
     * business and a module that guessed would be shipping somebody else's
     * design into their application.
     *
     *     #[Modules(AuthModule::class, login: App\Pages\LoginLayout::class)]
     *
     * Left unset, this package's own {@see LoginLayout} is used: plain, and it
     * works. It is the floor, not the intention.
     *
     * @param class-string $page a {@see \Empira\View\Layout} with a `#[Route('/login')]`
     */
    public function usePage(string $page): void
    {
        $this->loginPage = $page;
    }

    /**
     * {@see ConfigurableModule}, so an application can pass this without naming
     * the class.
     *
     * @param array<string, mixed> $options
     */
    public function configure(array $options): void
    {
        if (isset($options['login']) && is_string($options['login'])) {
            $this->usePage($options['login']);
        }

        if (isset($options['redirect']) && is_string($options['redirect'])) {
            $this->redirectAfterLogin = $options['redirect'];
        }
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

        $this->routes($app);
    }

    /**
 * The three URLs this module publishes.
 *
 * Skipped individually when the application has already claimed one, checked
 * with {@see RouteCollection::match()} rather than by name. A name check would
 * be useless: an application's page is a different class with a different name,
 * and the only thing the two share is the URL.
 *
 * **The POSTs keep CSRF, and the middleware is attached here.** They change
 * state, which is what the token is for, and an application that has not
 * installed {@see VerifyCsrfToken} globally would otherwise get a login form
 * that can be forged against. A module that publishes a POST protects its own.
 */
private function routes(Application $app): void
    {
        $routes = $app->routes();

        if ($routes->match('GET', self::LOGIN_PATH) === null) {
            // A layout class *name*, which is the framework's own "this URL
            // renders this page" form. The page is therefore rendered by
            // `Application::view()`, with the application's session and CSRF
            // wired in — and replacing this string replaces the handler's target
            // rather than competing with it for the path.
            $routes->get(self::LOGIN_PATH, $this->loginPage, 'auth.login');
        }

        $login = new LoginHandler($this->loginPage, $this->redirectAfterLogin);
        $logout = new LogoutHandler($this->redirectAfterLogin);

        $routes->group('', function (RouteCollection $routes) use ($login, $logout): void {
            if ($routes->match('POST', self::LOGIN_PATH) === null) {
                $routes->post(
                    self::LOGIN_PATH,
                    static fn(Request $r, Application $a, Auth $auth): Response => $login->handle($r, $a, $auth),
                    'auth.login.attempt',
                );
            }

            if ($routes->match('POST', self::LOGOUT_PATH) === null) {
                $routes->post(
                    self::LOGOUT_PATH,
                    static fn(Auth $auth): Response => $logout->handle($auth),
                    'auth.logout',
                );
            }
        }, middleware: [VerifyCsrfToken::class]);
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