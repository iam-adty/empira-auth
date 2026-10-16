<?php

declare(strict_types=1);

namespace Empira\Auth\Pages;

use Empira\Auth\AuthModule;
use Empira\Element;
use Empira\View\Layout;
use Empira\View\Region;

/**
 * The sign-in form, and this package's default for it.
 *
 * **It is a floor, not an intention.** A login page looks like the application
 * it lives in, and this package cannot know what that is — so an application
 * that has a layout should point the module at its own page instead:
 *
 *     #[Modules(AuthModule::class, login: App\Pages\LoginLayout::class)]
 *
 * What is here is plain, self-contained and works, for the application that
 * installs the module and has not yet drawn anything.
 *
 * **It carries no `#[Route]`.** The module owns the three URLs and points
 * `GET /login` at this class, so an application that replaces it replaces the
 * handler's target rather than competing with it for the same path.
 *
 * ## The form posts normally, not through htmx
 *
 * Signing in changes who the browser *is*, and the browser's idea of that is
 * its cookie — which only a real response to a real navigation sets. A swap
 * would update a fragment of a page the browser still believes is the logged-out
 * one, and the back button would walk through the other's history.
 *
 * ## The password is never rendered back
 *
 * The email is, because mistyping it is the most common reason a person is
 * standing at a login form again. The password is not, because a field that
 * echoes it is a field that has it in the page source.
 */
final class LoginLayout extends Layout
{
    protected function regions(): array
    {
        return [
            'main' => fn(Region $region): Element => $this->form($region),
        ];
    }

    private function form(Region $region): Element
    {
        $error = $region->data('error');

        $form = $this->hx->form()
            ->attr('method', 'post')
            ->attr('action', AuthModule::LOGIN_PATH)
            ->append(
                $this->hx->label('Email')
                    ->append(
                        $this->hx->input()
                            ->attr('name', 'email')
                            ->attr('value', (string) $region->data('email', ''))
                            ->attr('autocomplete', 'username'),
                    ),
                $this->hx->label('Password')
                    ->append(
                        $this->hx->input()
                            ->attr('name', 'password')
                            ->attr('type', 'password')
                            ->attr('autocomplete', 'current-password'),
                    ),
                $this->hx->button('Sign in')->attr('type', 'submit'),
            );

        // `csrf` is null under `bootConsole()`, where there is no browser and
        // nothing to protect. Omitting the field there is correct rather than a
        // fallback: the POST does not exist in a console.
        if ($this->csrf !== null) {
            $form->append(
                $this->hx->input()
                    ->attr('type', 'hidden')
                    ->attr('name', '_csrf')
                    ->attr('value', $this->csrf->token()),
            );
        }

        return $this->hx->div('login')
            ->append($this->hx->h1('Sign in'))
            ->append(
                $error === null
                    ? null
                    : $this->hx->p('login-error')->class('error')->text((string) $error),
            )
            ->append($form);
    }
}