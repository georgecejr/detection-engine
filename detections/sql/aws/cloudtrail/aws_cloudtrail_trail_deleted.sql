-- Sigma: aws_cloudtrail_trail_deleted
-- id: bd1e2195-46c0-4cb3-b2cb-d109daab8164
SELECT
    event_id,
    event_time,
    event_source,
    event_name,
    user_identity_arn,
    source_ip_address,
    aws_region,
    request_parameters
FROM cloudtrail_logs
WHERE event_source = 'cloudtrail.amazonaws.com'
  AND event_name = 'DeleteTrail'
