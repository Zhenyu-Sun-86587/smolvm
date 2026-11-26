ALTER TABLE lifecycle_protections ADD COLUMN first_launch_json TEXT
    CHECK(first_launch_json IS NULL OR json_valid(first_launch_json));
