<?php

declare(strict_types=1);

namespace Empira\Auth;

use Empira\ModuleOption;
use Empira\View\Layout;

/**
 * Which page this application's sign-in form is.
 *
 * ## Why it is here and not in the framework
 *
 * The framework publishes the *mechanism* — {@see ModuleOption}, and
 * {@see \Empira\Application::installModules()} to collect it. The option itself
 * belongs to the module that accepts it, which is why this is not in
 * `principle`: core carrying `login` would be core knowing something about an
 * auth module, and that is the coupling the interface exists to remove.
 *
 * ## Why it is an attribute at all
 *
 * It was `#[Modules(AuthModule::class, login: LoginLayout::class)]`, which PHP
 * will not accept — a variadic must be the last parameter, and nothing may
 * follow one. It also could not stay a constructor argument, because a module is
 * resolved by name and the container builds it.
 *
 * ## Why an application should almost always name one
 *
 * A login page looks like the application it lives in, and this package cannot
 * know what that is. {@see \Empira\Auth\Pages\LoginLayout} is the floor — plain,
 * self-contained, and it works — for an application that has not drawn anything
 * yet. Naming this attribute is how the real one gets used:
 *
 *     #[LoginPage(LoginLayout::class)]
 *
 * Declaring nothing is not an error. An absent attribute means "no opinion", and
 * the module falls back to the page it ships.
 */
#[\Attribute(\Attribute::TARGET_CLASS)]
final class LoginPage implements ModuleOption
{
    /**
     * @param class-string<Layout> $page the layout `GET /login` renders
     */
    public function __construct(public readonly string $page)
    {
    }

    /**
     * {@see ModuleOption}
     *
     * The key is this package's to choose — the framework merges whatever
     * arrives without looking at it, which is the whole arrangement.
     */
    public function options(): array
    {
        return ['login' => $this->page];
    }
}