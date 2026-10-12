# empira-auth

Authentication for [Empira](../principle), as a **module**.

Not on Packagist yet, so Composer has to be told where to look. Add both packages
to your `composer.json`:

```json
{
    "repositories": [
        { "type": "vcs", "url": "https://github.com/iam-adty/empira-principle.git" },
        { "type": "vcs", "url": "https://github.com/iam-adty/empira-auth.git" }
    ]
}
```

Then require **both**, naming the framework explicitly:

```bash
composer require iam-adty/empira-principle:dev-main iam-adty/empira-auth:dev-main
```

Naming the framework is not ceremony. Composer's default `minimum-stability` is
`stable`, so a transitive dependency on a `dev-` branch is rejected — and this
package's dependency on `empira-principle` is exactly that. Requiring it at the
root is what makes it installable:

    - iam-adty/empira-auth dev-main requires iam-adty/empira-principle dev-main
      -> found iam-adty/empira-principle[dev-main, 0.1.x-dev (alias of dev-main)]
      but it does not match your minimum-stability.

`:dev-main` is needed because there is no release to satisfy; `^0.1@dev` works too,
since both packages alias their branch as `0.1.x-dev`. When these reach Packagist,
the repository block and the suffixes both go away.

The alternative is `"minimum-stability": "dev"` in your root, which lets this
install with one `require` — and also lets any *other* dependency's development
branch through, which is a wider door than this problem needs.

The framework does not ship authentication, does not know this package's
classes, and boots without it. An application with no users has no `users` table
— which was not true until recently, and is the whole reason this is a package.

```
namespace Empira\Auth;     PHP ^8.4, MIT
```

## The split

Authentication is two halves, and only one of them needs the mechanism.

**Core keeps** (`Empira\Security`) — the read side, because a layout asking
"is anyone signed in" and CSRF asking "was this proven without a cookie" must
both work in an application that installed no auth module at all:

| | Answers |
|---|---|
| `Identity` | who is this? — an `id()`, and deliberately nothing else |
| `Guard` | given *this* request, whose credential is it? |
| `NonAmbientCredential` | marker: a browser will not send this credential by itself |
| `RequestUser` | the guards, asked once per request — `user/check/guest/id/guard` |
| `Module` | `register(Application)` — the one hook a module plugs into |

**The auth module provides** (`Empira\Auth`) — everything that writes, plus the
storage:

| | Answers |
|---|---|
| `User` | a Doctrine entity over `users` |
| `UserProvider` | which user is that id, and is this password theirs? |
| `SessionGuard`, `BearerGuard` | the two mechanisms this package ships |
| `Auth` | the façade: `RequestUser` narrowed to `User`, plus `login`/`logout` |
| `RequireAuth` | the middleware that refuses a request with nobody behind it |

`RequestUser` and `Auth` are **bound as two separate objects**, deliberately — see
[the trap](#why-two-objects-not-one) below.

## Wiring it

```php
$app->orm($config, [__DIR__, AuthModule::entityPath()]);
$app->module(new AuthModule([new SessionGuard($app->session(), $users)]));
```

`AuthModule::forApplication($app)` builds that guard list for you, for the common
case of a Doctrine-backed application:

```php
$app->orm($config, [__DIR__, AuthModule::entityPath()]);
$app->module(AuthModule::forApplication($app));
```

Both entity paths are needed. `__DIR__` is your application's own entities;
`AuthModule::entityPath()` is `User`. **The module does not add the entity path
for you**, because mapping your entities is a decision about your application
while adding this package's is a fact about this package. Drop it and nothing
fails at request time — see [the subtlety that hides it](#the-subtlety-that-hides-it).

Guards are consulted in order and the first user wins. Nothing happens until
`auth()` is called, so an application with no users pays nothing. Once the module
is its own package, this becomes `$app->module(new AuthModule(...))`.

## Asking

```php
// Anything the framework provides — a layout, a route, CSRF:
public function __construct(private readonly RequestUser $user) {}

$this->user->user();    // Identity|null — whatever a guard produced
$this->user->check();   // bool
$this->user->id();      // int|string|null
$this->user->guest();   // bool

// Anything in the auth module, or an app that installed it:
public function __construct(private readonly Auth $auth) {}

$this->auth->user();    // User|null — narrowed
$this->auth->login($user);   // writes
$this->auth->logout();       // writes
```

Both bindings are **per request**, not once at boot. That is the reason they need
no `reset()`: a fresh instance cannot remember the request before it. A singleton
would need resetting before every dispatch, and a reset someone forgets is a
request that runs as the user before it — the same failure this codebase has
already produced twice, for route parameters and for flash messages.

## Requiring a user

```php
$app->use(RequireAuth::class);                                     // everywhere
$routes->group('/admin', $routes, middleware: [RequireAuth::class]); // a group
#[Route('/admin', middleware: [RequireAuth::class])]                // one route
```

It **throws** `HttpException::unauthorized()` rather than returning a 401.
Middleware runs inside `Application::handle()`'s try block, so a throw is
rendered by the same code as every other failure:

```
GET /admin                 → 401, the onHttpError view
GET /admin  Accept: json   → 401, {"error":{"status":401,"message":"…"}}
```

Returning a `Response` would mean copying that envelope a third time, and the
first copy that drifts is the one nobody tests.

With no `Auth` bound — a middleware built by hand, say — it refuses. Auth fails
closed.

## The guards

### SessionGuard

The session cookie is an **ambient** credential: the browser attaches it to
every request to this site without being asked.

```php
$auth->login($user);   // rotates the session id, then stores the id
$auth->logout();
```

The rotation is not decoration. Without it, an id an attacker planted before
the victim signed in is still valid afterwards — session fixation.
`Session::regenerate()` is a no-op under the CLI, so a test watching the id
change would pass whether or not anything happened; `SessionGuard` therefore
takes a `SessionId` and the test asserts the rotation was *requested*.

### BearerGuard

An `Authorization: Bearer …` header. What the token means is the
application's business, so the check is a closure:

```php
new BearerGuard(fn(string $token): ?User => $users->byApiToken($token));
```

The token is never logged and never quoted in an exception — a message
containing the credential puts it in a log file.

## Users

```php
$users = new DoctrineUserProvider($app->entities());  // the ORM

$user = $users->byId(7);
$user = $users->byCredential('ada@example.com');
$users->verifyPassword($user, 'correct horse');
$users->hash('correct horse');                     // to store one
```

`password_hash` and `password_verify` are PHP's own, so no dependency stands
between a password and a secure hash. A user with no stored hash fails to
authenticate — a missing column must not read as "any password works".

The hash is reachable only through `passwordHash()`, which a view never calls:
the properties are not public, so an exception carrying a user cannot serialise
one by accident.

**`User` is an entity.** That is the change, and it has consequences worth
stating rather than discovering:

```php
$user->id();          // was $user->id — the id is assigned by the ORM
$user->email();
$user->name();
```

- **A `User` that came from a guard is *managed*.** It belongs to an
  EntityManager. A lazy association read outside the request that loaded it
  throws, so do not hold one anywhere longer than the request.
- **The identity map means "the same object" within a request.** Between
  requests the manager is cleared, so the next one reads the database again.
- **The framework maps the `users` table.** A large opinion, held deliberately:
  adding columns to `User` is how an application extends what auth knows about.
  An application that needs a different shape maps its own entity behind the
  same `UserProvider`.

**`UserProvider` was the ORM seam, and it earned it.** `SessionGuard`, every
middleware and every component talked to this interface and never to a row — so
the day `User` became an entity, nothing above this line had to change.

## CSRF and what is exempt

Read the framework's [docs/http.md](../principle/docs/http.md#csrf) for the
mechanism. What matters here is *which* requests are exempt, and the answer is
not "requests with a user".

CSRF defends **ambient** credentials — cookies the browser attaches by itself.
Two kinds of request are therefore not a CSRF problem:

1. **A valid bearer token.** An `Authorization` header is not ambient: a
   cross-site page cannot set one without a CORS preflight this server has to
   approve. There is nothing to forge.
2. **A route that says so** — `#[Route('/webhook', csrf: false)]`, or
   `$routes->post('/webhook', $handler, csrf: false)`.

A request with a session cookie, a user, and no token has a user and **is still
exactly the forgery CSRF exists for**. So `Auth` reports *which* guard answered,
not merely that one did, and there is a test that fails if anyone widens the
check to "any authenticated user".

The route flag is read by the CSRF middleware itself. It cannot be read by a
route middleware, because that runs *inside* the check — by the time it could
report anything, the request has already been refused.

## What is deliberately not here

- **Password hashing policy, registration, reset, email verification.** Those
  are application decisions with real consequences, and a framework that
  guesses them is a framework that gets them wrong.
- **Rate limiting on `login()`.** Belongs at the edge; see [SECURITY.md](../principle/SECURITY.md).
- **Roles and permissions.** `User::$attributes` is yours; the framework does
  not know what an administrator is.

## Why two objects, not one

The framework binds `Security\RequestUser` per request; this package binds `Auth`
separately. They are separate objects on purpose, and the reason is a trap that
looks like tidiness.

`Auth` narrows `RequestUser::user()` to `User`. Bind one object under both names
to avoid constructing two — which is the obvious thing to do — and every
`RequestUser` answer comes back narrowed. A guard returning any other `Identity`
is reported as **nobody**: it authenticates, and the application reads it as
anonymous. PHP accepts this without complaint, because narrowing a return type
is legal.

The symptom is the worst shape a type mistake can take. Nothing errors, nothing
logs, and the failure reads as "the feature does not work" rather than as two
objects being interchangeable when they are not.

## The subtlety that hides it

Doctrine separates **discovery** from **lookup**. `getClassMetadata(User::class)`
reflects on the class you *name*, so it resolves whether or not `User`'s
directory was registered — which means forgetting `AuthModule::entityPath()`
changes nothing at request time.

What breaks is `getAllClassNames()`, which scans the registered paths and is what
the schema tooling reads. So the cost is not an exception: it is a `SchemaTool`
quietly generating DDL that omits a table an entity depends on.

## The migrations

The `users` table ships here, in `Empira\Migrations\Auth`. Two things about that
namespace are load-bearing:

- **It is not the project's `Empira\Migrations`.** Doctrine keys its lookup by
  namespace, so sharing one means two files declaring the same class name — and
  which one runs depends on which `require` reached the definition first. That
  reads as a successful migration either way.
- **`empira migrate` must be handed the booted application** for it to find this
  directory at all. `bin/empira` does; anything else driving the console has to.

## Further reading

- [AGENTS.md](https://github.com/iam-adty/empira-auth/blob/main/AGENTS.md) — the conventions, and the traps above in short form
- [SECURITY.md](../principle/SECURITY.md) — the trust boundaries
- [../principle/docs/data.md](../principle/docs/data.md) — where entities come from
- [../principle/docs/routing.md](../principle/docs/routing.md) — attaching middleware to a route
