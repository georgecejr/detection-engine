SELECT
    eventName,
    eventSource,
    userIdentity.type,
    userIdentity.accountId,
    awsRegion,
    srcIP,
    readOnly
FROM aws_cloudtrail_logs
WHERE eventName = 'PutBucketEncryption'
  AND eventSource = 's3.amazonaws.com'
  AND readOnly = false
