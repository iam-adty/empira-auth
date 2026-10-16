<?php

declare(strict_types=1);

namespace Empira\Auth;

use Empira\Application;
use Empira\Http\Request;
use Empira\Http\Response;

/**
 * `POST /login` — check a credential and a password, and sign in.
 *
 * ## One answer for every failure
 *
 * An unknown credential and a wrong password produce the same response with the
 * same message. Distinguishing them would tell an attacker which half of a guess
 * was right, and a login form is the most attacked form there is.
 *
 * ## Why a full response, and not a swap
 *
 * A successful sign-in changes who the browser *is*, and the browser's own idea
 * of that is its cookie — which only a real response to a real navigation
 * sets. A swap would replace a fragment of a page the browser still believes is
 * the logged-out one.
 *
 * The failure path is a full response too, for a simpler reason: it re-renders
 * **the same page class** with an error, so there is exactly one copy of the
 * form. A handler that rebuilt the markup would be a second form to keep in
 * step, and it would drift from the page within a week.
 */
final class LoginHandler
{
    /** @param class-string $page the layout the application chose for `GET /login` */
    public function __construct(
        private readonly string $page,
        private readonly string $redirect = '/',
    ) {
    }

    public function handle(Request $request, Application $app, Auth $auth): Response
    {
        $credential = $request->string('email');
        $password = $request->string('password');

        $user = $auth->attempt($credential, $password);

        if ($user === null) {
            return $app->view($this->page, [
                'error' => 'Those credentials did not work.',
                'email' => $credential,
            ]);
        }

        return Response::redirectTo($this->redirect);
    }
}