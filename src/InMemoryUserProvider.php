<?php

declare(strict_types=1);

namespace Empira\Auth;

/**
 * A guard over a list held in memory.
 *
 * For tests, for a console command, and for the reference application's
 * demonstration. It is not a user store, and nothing should treat it as one —
 * every process gets its own copy, so a signed-in user does not survive the
 * request that signed them in.
 */
final class InMemoryUserProvider implements Guard
{
    /**
     * @param array<int|string, User> $users keyed by id
     */
    public function __construct(private readonly array $users = [])
    {
    }

    public function identify(\Empira\Http\Request $request): ?User
    {
        $id = $request->header('x-demo-user');

        if ($id === null || !array_key_exists($id, $this->users)) {
            return null;
        }

        return $this->users[$id];
    }
}
