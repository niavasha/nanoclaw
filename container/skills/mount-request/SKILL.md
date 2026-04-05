# Mount Request

Request access to host directories outside your sandbox. Access is time-boxed (default 30 minutes) and requires user approval.

## When to Use

When the user asks you to work with files in a directory you don't have access to (e.g., ~/Documents, ~/Desktop, ~/Downloads, or any other host path).

## How to Request Access

Write a JSON file to the IPC tasks directory:

```bash
cat > /workspace/ipc/tasks/$(date +%s)-mount-request.json << 'EOF'
{
  "type": "request_mount",
  "path": "~/Documents",
  "readonly": true,
  "reason": "User asked me to find a file in their Documents folder"
}
EOF
```

The host will ask the user to approve. You will receive a system message when approved or denied.

## How to Use an Approved Mount

After approval, send a mount_task IPC command with the grant ID from the approval message:

```bash
cat > /workspace/ipc/tasks/$(date +%s)-mount-task.json << 'EOF'
{
  "type": "mount_task",
  "grantId": "<grant-id-from-approval-message>",
  "prompt": "List all PDF files in the Documents directory and provide a summary of each filename"
}
EOF
```

A subagent with the mounted directory will run the task and return the results to you via a system message.

## Important Notes

- Access is **time-boxed** — default 30 minutes, then automatically revoked
- The user can specify a custom duration when approving (e.g., "yes 60" for 60 minutes)
- The mounted directory appears at `/workspace/extra/<dirname>` in the subagent
- You can send multiple mount_task commands while the grant is active
- Request `readonly: true` unless the user explicitly asks you to modify files
- Paths containing `.ssh`, `.env`, `credentials`, or similar sensitive patterns are always blocked
