<?php

declare(strict_types=1);

namespace Empira\Auth;

use Empira\Http\Request;
use Empira\Security\Guard as SecurityGuard;

/**
 * A guard that answers with a {@see User} rather than a bare identity.
 *
 * This is the module's narrowing of {@see SecurityGuard}: the core contract
 * promises an {@see \Empira\Security\Identity}, and a session or bearer guard
 * in this package can say more precisely which one it will return. Narrowing a
 * return type is legal in PHP, so the guards here satisfy the core contract
 * without the core ever mentioning `User`.
 */
interface Guard extends SecurityGuard
{
    public function identify(Request $request): ?User;
}
