-- Sigma: okta_user_created
-- id: c59a3120-51af-427a-9fa6-9567cf391b9b
SELECT
    event_id,
    published,
    actor_alternate_id,
    target_alternate_id,
    event_type,
    outcome_result
FROM okta_system_logs
WHERE event_type = 'user.lifecycle.create'
