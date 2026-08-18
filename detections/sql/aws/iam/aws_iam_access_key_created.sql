-- Sigma: aws_iam_access_key_created
-- id: d57dbb88-eea3-4724-ba0e-826cf42b2dad
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
  AND event_name = 'CreateAccessKey'
