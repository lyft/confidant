---
title: Upgrading
---

# Upgrading

Most Confidant changes are backwards compatible, so upgrading is usually just
installing a newer version. In some cases, though, we need to make breaking
changes that may require action on your part to upgrade. The below sections
document breaking changes and how to upgrade when they occur.

## Upgrading to 2.0.0 or 3.0.0

Due to breaking changes in PynamoDB, to upgrade to 2.0.0 or 3.0.0 may require
some data migration.

PynamoDB changed its data model over a series of releases, which requires
the upgrade path for Confidant to follow the same model. To upgrade to 3.0.0,
it's necessary to first upgrade to 2.0.0 and perform a data migration. Once
you've performed a data migration, if you need to downgrade, you must
downgrade to 1.11.0, which is backwards compatible with all other
versions of Confidant.

### Performing the data migration

Confidant 2.0.1 ships with two maintenance scripts for the data migration:

```bash
cd /srv/confidant
source venv/bin/activate

# Encrypt the data
python manage.py migrate_blind_cred_set_attribute
python manage.py migrate_service_set_attribute
```

These scripts may fail intermittently. If any failures are occur, retry the
script until all objects are fully migrated.

2.0.0 ships with the ability to enable a maintenance mode, which you may want
to enable when upgrading to 2.0.0. Putting Confidant into maintenance mode
will disallow any writes via the API, ensuring that blind credentials with the
new data format aren't written until you've run the maintenance script. This
is useful to allow you to downgrade to an older version, if necessary. See the
[maintenance mode settings docs](https://lyft.github.io/confidant/basics/configuration/#maintenance-mode-settings)
for how to enable maintenance mode.

## Upgrading to 4.0.0

Due to breaking changes in PynamoDB, to upgrade to 4.0.0 will require a data
migration. Before migrating to 4.0.0, ensure that you are at least on 3.0.0.

PynamoDB changed its data model over a series of releases, which requires the
the upgrade path for Confidant to follow the same model. After performing this
data migration, the data is still compatible with 3.0.0, but not below this.

### Peforming the data migration for 4.0.0

Confidant 4.0.0 ships with a maintenance script for the data migration:

```bash
cd /srv/confidant
source venv/bin/activate

# Encrypt the data
python manage.py migrate_boolean_attribute
```

This script may fail intermittently. If any failures are occur, retry the
script until all objects are fully migrated.
