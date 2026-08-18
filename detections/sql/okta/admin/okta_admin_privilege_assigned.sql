-- Sigma: okta_admin_privilege_assigned
-- id: f8603214-b75e-4506-bb35-4295e81da5a0
SELECT
    event_id,
    published,
    actor_alternate_id,
    target_alternate_id,
    event_type,
    privilege_granted,
    outcome_result
FROM okta_system_logs
WHERE event_type IN ('user.account.privilege.grant', 'iam.role.assign')
  AND (
      privilege_granted ILIKE '%Super Administrator%'
      OR privilege_granted ILIKE '%Organization Administrator%'
      OR privilege_granted ILIKE '%Application Administrator%'
  )
