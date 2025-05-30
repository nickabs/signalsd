-- name: CreateSignalBatch :one
INSERT INTO signal_batches (
    id,
    created_at,
    updated_at,
    isn_id,
    account_id,
    is_latest,
    account_type
) VALUES (
    gen_random_uuid(), 
    now(), 
    now(), 
    $1, 
    $2, 
    TRUE,
    $3
)
RETURNING *;

-- name: CloseISNSignalBatchByAccountID :execrows
UPDATE signal_batches 
SET is_latest = FALSE
WHERE isn_id = $1 and account_id = $2;

-- name: GetLatestIsnSignalBatchByAccountID :one
SELECT * FROM signal_batches 
WHERE isn_id = $1 
AND account_id = $2
AND is_latest = TRUE;

-- name: GetLatestSignalBatchByIsnSlugAndBatchID :one
SELECT * FROM signal_batches sb
JOIN isn i 
ON i.id = sb.isn_id
WHERE i.slug = $1 
AND sb.id = $2
AND sb.is_latest = TRUE;