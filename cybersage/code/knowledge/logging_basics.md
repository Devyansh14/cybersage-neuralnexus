## Security logging basics
Security logs record events such as logins, failed logins, permission changes and blocked connections. Useful entries include a timestamp, event type, user, source address and result. Logs help detect and investigate incidents, but a single line rarely proves an attack: patterns across several entries matter more. Logs should never contain passwords, tokens or other secrets; if they do, remove or mask them before sharing or analysing.

## Reading uncertainty
Say how sure you are. Few entries, missing timestamps, or events that have innocent explanations mean low confidence. Do not call an attack confirmed from logs alone; recommend verification steps instead.

## Normal activity
Successful logins followed by logouts, occasional single failed logins, and routine allowed connections are normal and should not be flagged as threats.
