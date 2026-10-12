<?php

declare(strict_types=1);

namespace Empira\Migrations\Auth;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * The bag a user carries anything extra in.
 *
 * Added when `Auth\User` became an entity rather than a value object. The old
 * `attributes` array was free — it lived in PHP and never reached a column — so
 * a user could carry whatever the application liked without a migration. Making
 * it an entity means the columns are the mapping, and the bag has to be one of
 * them if it is to survive.
 *
 * The dialect branch is the same one the first migration had for the
 * auto-incrementing key, and it comes back for the same reason: there is no
 * column type both servers spell the same way. Asking DBAL for the type through
 * the Schema is better than writing `CLOB` and having PostgreSQL answer
 * `type "clob" does not exist`, which is what happened.
 *
 * Nullable rather than defaulting to an empty object: a row written before this
 * migration has no bag, and `null` says that honestly where `{}` would claim it
 * had been emptied on purpose.
 */
final class Version20261012000001 extends AbstractMigration
{
    public function up(Schema $schema): void
    {
        $schema->getTable('users')->addColumn(
            'attributes',
            $this->connection->getDatabasePlatform() instanceof PostgreSQLPlatform ? 'jsonb' : 'text',
            ['notnull' => false],
        );
    }

    public function down(Schema $schema): void
    {
        $schema->getTable('users')->dropColumn('attributes');
    }
}