-- Sigma: aws_cloudtrail_stopped
-- id: c53e9f08-dbd4-4a4f-b29e-fb5117d6960e
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
  AND event_name = 'StopLogging'
