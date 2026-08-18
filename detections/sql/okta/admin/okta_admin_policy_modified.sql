-- Sigma: okta_admin_policy_modified
-- id: 914c1d22-fd78-4537-814d-d8511368283f
SELECT
    event_id,
    published,
    actor_alternate_id,
    event_type,
    target_display_name,
    outcome_result
FROM okta_system_logs
WHERE event_type IN (
    'application.policy.sign_on.update',
    'policy.lifecycle.update',
    'policy.rule.update'
)
