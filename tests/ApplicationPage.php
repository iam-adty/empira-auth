<?php

declare(strict_types=1);

namespace Empira\Auth\Tests;

use Empira\Element;
use Empira\View\Layout;
use Empira\View\Region;

/**
 * An application's own login page, used to prove the module's seam works.
 *
 * It has no form, because its only job is to be unmistakably *this* page
 * rather than the module's — a test asserting on shared markup could pass
 * against either.
 */
final class ApplicationPage extends Layout
{
    protected function regions(): array
    {
        return [
            'main' => static fn(Region $region): Element => $region->element('p')->text('the application draws this'),
        ];
    }
}