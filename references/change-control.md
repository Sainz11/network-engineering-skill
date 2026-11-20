# Change Control and Rollback

Before any production change:
- Confirm owner, authorization, maintenance window, affected customers/services.
- Export/backup config and verify the backup is readable.
- Record baseline: interface state/counters, routing, CPU/memory, latency/loss, wireless metrics, alarms.
- Define exact commands/GUI steps and expected output.
- Identify out-of-band access and rollback path.
- Make one logical change at a time.
- Verify service from both device and end-user perspectives.
- Roll back if success criteria fail or impact exceeds the approved threshold.
- Record timestamps, operator, change, evidence, and outcome.

Never treat a successful command response as proof that service is healthy.
