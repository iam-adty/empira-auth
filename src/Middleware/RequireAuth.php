<?php

declare(strict_types=1);

namespace Empira\Auth\Middleware;

use Closure;
use Empira\Auth\Auth;
use Empira\Http\Middleware;
use Empira\Http\Request;
use Empira\Http\Response;
use Empira\Routing\HttpException;

/**
 * Refuses a request that has no user behind it.
 *
 *     $app->use(RequireAuth::class);                                  // everywhere
 *     $routes->group('/admin', $routes, middleware: [RequireAuth::class]);
 *     #[Route('/admin', middleware: [RequireAuth::class])]
 *
 * It **throws** rather than returning a 401. Middleware runs inside
 * `Application::handle()`'s try block, so a throw is rendered by the same code
 * that renders every other failure: the negotiated JSON envelope for a client
 * that asked for JSON, the `onHttpError` view for a browser, and the right
 * status code — without this class knowing what any of those look like.
 *
 * Handing back a `Response` instead would mean copying that envelope a third
 * time, and the first copy that drifts is the one nobody tests.
 */
final class RequireAuth implements Middleware
{
    /**
     * Injected per request by {@see \Empira\Application}.
     *
     * Nullable so a middleware built by hand — in a test, or by a console
     * command — constructs rather than explodes. An `Auth` with no guards can
     * never find a user, so that path refuses rather than admits.
     */
    public function __construct(private readonly ?Auth $auth = null)
    {
    }

    public function handle(Request $request, Closure $next): Response
    {
        if (($this->auth ?? new Auth([], $request))->guest()) {
            throw HttpException::unauthorized('Sign in to continue.');
        }

        return $next($request);
    }
}
