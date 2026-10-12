# AGENTS.md

> **Status: describes shipped code.** Current behaviour, verified against `37 tests, 71 assertions`.

Guidance for AI agents and new contributors working on the Empira auth module.

## What this is

`iam-adty/empira-auth` — authentication for [Empira](../principle), as a
**module**. The framework does not ship it, does not know its classes, and boots
without it.

```
namespace Empira\Auth;     PHP ^8.4, MIT
```

It is a module because authentication used to be in the framework's spine:
`Application` imported `Auth`, built one every request, and `orm()` would not
describe a configuration without mapping a `users` table first. Every application
carried a users table whether or not it wanted one. That dependency ran *inward*
— core to feature — which is the direction that cannot be cut.

## The line between the two packages

**The framework keeps** the read half, in `Empira\Security`:

| | Answers |
|---|---|
| `Identity` | who is this — an `id()`, and nothing else |
| `Guard` | given this request, whose credential is it |
| `RequestUser` | the guards asked once: `user/check/guest/id/guard` |
| `NonAmbientCredential` | marker: a browser will not send this by itself |
| `Module`, `MigrationSource` | the hooks this package plugs into |

**This package keeps** everything that writes, and everything that knows what a
user is: `User` (a Doctrine entity), `UserProvider` and its two implementations,
`SessionGuard`, `BearerGuard`, `RequireAuth`, and `Auth` — the façade that adds
`login()`/`logout()` and narrows `RequestUser` to a `User`.

Never make core depend on anything here. If a class in this package seems to
belong in the framework, the question is whether the framework can answer it
*without knowing what a user is* — usually it can.

## Commands

```bash
composer test                      # the whole suite
vendor/bin/phpunit tests/AuthTest.php
```

The suite runs against SQLite by default and needs no services. It links the
framework through a Composer path repository:

```bash
composer config repositories.principle path ../principle
composer update iam-adty/empira-principle
```

An edit under `principle/src` is live immediately; no rebuild, no reinstall.

## Wiring it

```php
$app->orm(self::databaseConfig(), [__DIR__, AuthModule::entityPath()]);
$app->module(new AuthModule([new SessionGuard($app->session(), $users)]));
```

`AuthModule::forApplication($app)` builds the common case in one call. The entity
path is the one thing the module does not add for you: mapping an application's
own entities is a decision about that application, while adding this package's is
a fact about this package.

## Conventions

- **Plans go in the todo tool**, so they show in the opencode TUI sidebar.
- **Edit source with the Edit tool**, not `sed -i` or a rewriting heredoc.
  Shell is for reading: `grep`, `find`, `git diff`, `php -l`.
- `declare(strict_types=1);` first in every PHP file.
- `final class` or `enum`; an interface only where there is genuinely more than
  one implementation.
- Constructor property promotion; `private readonly` where the value is fixed.
- Explanation belongs in docblocks, not inline comments.
- Typed PHPDoc: `@param list<Guard> $guards`, `@return array<string, string>`.
- Tests: `final class XTest extends TestCase`, names that read as behaviour,
  `assertSame` over `assertEquals`.
- No emojis.

## Known traps

**Do not bind `Auth` under `RequestUser`, or bind one object for both.** The
framework binds `RequestUser` itself; this package binds `Auth` separately. They
are separate objects on purpose. `Auth` narrows `user()` to `User`, so serving
both from one object means a guard returning any *other* `Identity` is silently
reported as **nobody** — the guard authenticates and the application reads it as
anonymous. PHP accepts it; narrowing a return type is legal, so nothing
complains. The symptom looks like a broken feature rather than a type mistake.

**The `Auth` binding must be `bind`, never `singleton`.** It is built from the
application's current `Request`, and under a long-running worker a shared
instance is a façade frozen at whichever request first resolved it — request two
served as request one, silently.

**The migration namespace is load-bearing.** `users` lives in
`Empira\Migrations\Auth`, not the project's `Empira\Migrations`, because Doctrine
keys its lookup by namespace and this is a different directory. Sharing it means
two files declaring the same class name, and which one runs depends on which
`require` got there first.

**A `SessionGuard` needs the *application's* session, not a new one.** Building
a `Session` inside `AuthModule` produces a guard reading a session nothing
writes — a login form that reports "wrong password" forever.

## Definition of done

- [ ] `composer test` passes, and you added a test that fails without your change
- [ ] `php -l` is clean on every file you touched
- [ ] Nothing in this file describes something that does not exist
- [ ] No new dependency on the framework's internals from this package
