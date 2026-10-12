<?php

declare(strict_types=1);

namespace Empira\Migrations\Auth;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * The users table, and only that.
 *
 * Two notes on what is *not* here: a `remember_token` column, and an index on
 * the credential column. Both arrive with the feature that needs them, which is
 * the whole argument for migrations over a hand-run schema file.
 *
 * The auto-incrementing primary key no longer branches on the dialect. It used
 * to — SQLite wanted AUTOINCREMENT and PostgreSQL wanted SERIAL, and the
 * migration carried the `if` itself, which was noted at the time as the
 * clearest argument for having a schema builder. Describing the column with
 * `autoincrement` lets the platform decide, which is the same statement in both
 * dialects and half the file gone.
 */
final class Version20261011000001 extends AbstractMigration
{
    public function up(Schema $schema): void
    {
        $users = $schema->createTable('users');
        $users->addColumn('id', 'integer', ['autoincrement' => true]);
        $users->setPrimaryKey(['id']);
        $users->addColumn('email', 'string', ['length' => 255]);
        $users->addColumn('name', 'string', ['length' => 255]);
        $users->addColumn('password_hash', 'string', ['length' => 255]);

        // Named, because the portable spelling of "this column is unique" is a
        // constraint and not an index, and a register showing three anonymous
        // `users_email_...` entries helps nobody.
        $users->addUniqueIndex(['email'], 'users_email_unique');
    }

    public function down(Schema $schema): void
    {
        $schema->dropTable('users');
    }
}