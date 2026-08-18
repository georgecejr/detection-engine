-- Sigma: okta_mfa_factor_reset
-- id: 2d4d54ee-9656-4502-b779-6d12d31b1e6e
SELECT
    event_id,
    published,
    actor_alternate_id,
    actor_display_name,
    client_ip_address,
    event_type,
    outcome_result
FROM okta_system_logs
WHERE event_type = 'user.mfa.factor.reset_all'
