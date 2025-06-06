-- name: CreateSignalType :one

INSERT INTO signal_types (
    id,
    created_at,
    updated_at,
    isn_id,
    slug,
    schema_url,
    readme_url,
    title,
    detail,
    sem_ver,
    is_in_use
    ) VALUES (gen_random_uuid(), now(), now(), $1, $2, $3, $4, $5, $6, $7, true)
RETURNING *;

-- name: UpdateSignalTypeDetails :execrows
UPDATE signal_types SET (updated_at, readme_url, detail, is_in_use) = (NOW(), $2, $3, $4)
WHERE id = $1;

-- name: GetSignalTypes :many

SELECT sd.*
FROM signal_types sd;

-- name: GetSignalTypeByID :one

SELECT sd.*
FROM signal_types sd
WHERE sd.id = $1;

-- name: GetSignalTypeBySlug :one

SELECT sd.*
FROM signal_types sd
WHERE sd.slug = $1
AND sd.sem_ver = $2;

-- name: GetForDisplaySignalTypeByID :one
SELECT 
    sd.id,
    sd.created_at,
    sd.updated_at,
    sd.slug,
    sd.schema_url,
    sd.readme_url,
    sd.title,
    sd.detail,
    sd.sem_ver,
    sd.is_in_use
FROM signal_types sd
WHERE sd.id = $1;

-- name: GetForDisplaySignalTypeBySlug :one
SELECT 
    sd.id,
    sd.created_at,
    sd.updated_at,
    sd.slug,
    sd.schema_url,
    sd.readme_url,
    sd.title,
    sd.detail,
    sd.sem_ver,
    sd.is_in_use
FROM signal_types sd
WHERE sd.slug = $1
  AND sd.sem_ver = $2;

-- if there are no signals defs for the supplied slug, this query returns an empty string for schema_url and a sem_ver of '0.0.0' 
-- name: GetSemVerAndSchemaForLatestSlugVersion :one
SELECT '0.0.0' AS sem_ver,
       '' AS schema_url
WHERE NOT EXISTS
    (SELECT 1
     FROM signal_types sd1
     WHERE sd1.slug = $1)
UNION ALL
SELECT sd2.sem_ver,
       sd2.schema_url
FROM signal_types sd2
WHERE sd2.slug = $1
  AND sd2.sem_ver =
    (SELECT max(sd3.sem_ver)
     FROM signal_types sd3
     WHERE sd3.slug = $1);

-- only return signal_types for the ISN that are flagged "in use"
-- name: GetInUseSignalTypesByIsnID :many
SELECT sd.*
FROM signal_types sd
WHERE sd.isn_id = $1
AND is_in_use = true;

-- name: ExistsSignalTypeWithSlugAndSchema :one
SELECT EXISTS
  (SELECT 1
   FROM signal_types
   WHERE slug = $1
   AND schema_url = $2) AS EXISTS;