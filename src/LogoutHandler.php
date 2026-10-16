<?php

declare(strict_types=1);

namespace Empira\Auth;

use Empira\Http\Request;
use Empira\Http\Response;

/**
 * `POST /logout` — forget the session.
 *
 * A POST rather than a GET, and the reason is not tidiness: a GET is something
 * a browser will do on its own from a prefetch, from an `<img>` somebody pasted,
 * or from a link a mail client followed. Any of those could sign a person out,
 * and any of them is reachable by a third party who did not have to be trusted.
 *
 * Signing out changes state, so it belongs behind the same CSRF check as
 * signing in.
 */
final class LogoutHandler
{
    public function __construct(private readonly string $redirect = '/')
    {
    }

    public function handle(Auth $auth): Response
    {
        $auth->logout();

        return Response::redirectTo($this->redirect);
    }
}