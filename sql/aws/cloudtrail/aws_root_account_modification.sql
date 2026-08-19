SELECT
    eventName,
    eventSource,
    userIdentity.type,
    userIdentity.accountId,
    awsRegion,
    srcIP,
    readOnly
FROM aws_cloudtrail_logs
WHERE userIdentity.type = 'Root'
  AND readOnly = false
