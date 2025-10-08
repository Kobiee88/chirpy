-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens (token, user_id, expires_at, created_at)
VALUES ($1, $2, $3, $4)
RETURNING token, user_id, expires_at, created_at, updated_at, revoked_at;

-- name: GetUserIdFromRefreshToken :one
SELECT u.id
FROM users u
JOIN refresh_tokens rt ON u.id = rt.user_id
WHERE rt.token = $1 AND (rt.expires_at IS NULL OR rt.expires_at > NOW()) AND rt.revoked_at IS NULL;

-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens
SET revoked_at = NOW(), updated_at = NOW()
WHERE token = $1;