-- Sigma: aws_iam_policy_changed
-- id: e1ff68e8-2c89-4d7d-9140-6d580aadf8c1
SELECT
    event_id,
    event_time,
    event_source,
    event_name,
    user_identity_arn,
    source_ip_address,
    request_parameters
FROM cloudtrail_logs
WHERE event_source = 'iam.amazonaws.com'
  AND event_name IN (
      'CreatePolicy',
      'CreatePolicyVersion',
      'AttachUserPolicy',
      'AttachRolePolicy',
      'AttachGroupPolicy',
      'PutUserPolicy',
      'PutRolePolicy',
      'PutGroupPolicy'
  )
