<?php

declare(strict_types=1);

namespace Empira\Auth;

use Empira\Http\Request;
use Empira\Security\NonAmbientCredential;

/**
 * Signs a user in with an `Authorization: Bearer …` header.
 *
 * The header is *not* an ambient credential: a browser will not attach it on
 * its own, and a cross-site page cannot set one without a CORS preflight the
 * server has to approve. That asymmetry is the reason this guard is exempt from
 * CSRF checks, and the reason {@see Guard} implementations should say
 * explicitly which kind of credential they consume.
 *
 * What the token means is the application's business, so the check is a
 * closure:
 *
 *     $guard = new BearerGuard(fn(string $token): ?User => $users->byApiToken($token));
 *
 * The token is never logged and never appears in an error message: an
 * exception that quotes the credential puts it in a log file.
 */
final class BearerGuard implements Guard, NonAmbientCredential
{
    public const DEFAULT_SCHEME = 'Bearer';

    /** @var \Closure(string): (User|null) */
    private readonly \Closure $verify;

    /**
     * @param callable(string): (User|null) $verify what a token means to this application
     */
    public function __construct(
        callable $verify,
        private readonly string $scheme = self::DEFAULT_SCHEME,
        private readonly string $header = 'authorization',
    ) {
        $this->verify = $verify instanceof \Closure
            ? $verify
            : \Closure::fromCallable($verify);
    }

    public function identify(Request $request): ?User
    {
        $header = $request->header($this->header);

        if ($header === null) {
            return null;
        }

        $prefix = $this->scheme . ' ';

        // Case-insensitive, because the scheme is defined that way in RFC 7235
        // and every client library sends it however it likes.
        if (strlen($header) <= strlen($prefix) || strcasecmp(substr($header, 0, strlen($prefix)), $prefix) !== 0) {
            return null;
        }

        $token = trim(substr($header, strlen($prefix)));

        if ($token === '') {
            return null;
        }

        return ($this->verify)($token);
    }
}
