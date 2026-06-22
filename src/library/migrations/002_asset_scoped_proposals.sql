-- Asset-scoped profile proposals no longer store whole-profile proposal version/base fields.
-- Live 001 already created these columns, so remove them with a forward migration.
ALTER TABLE IF EXISTS {{tables.proposals}}
    DROP COLUMN IF EXISTS profile_version,
    DROP COLUMN IF EXISTS base_profile_version,
    DROP COLUMN IF EXISTS base_profile_digest;
