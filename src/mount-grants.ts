/**
 * JIT Mount Grants — time-boxed directory access for container agents.
 *
 * Manages the lifecycle of mount grants: pending → active → expired.
 * Updates the allowlist file and group config when grants are approved/revoked.
 */
import fs from 'fs';
import os from 'os';
import path from 'path';

import { MOUNT_ALLOWLIST_PATH, STORE_DIR } from './config.js';
import { runMountSubagent } from './container-runner.js';
import { resolveGroupIpcPath } from './group-folder.js';
import { logger } from './logger.js';
import { clearMountAllowlistCache } from './mount-security.js';
import { MountAllowlist, MountGrant } from './types.js';

const GRANTS_FILE = path.join(STORE_DIR, 'mount-grants.json');
const DEFAULT_DURATION_MINUTES = 30;

// In-memory state
const pendingGrants = new Map<string, MountGrant>(); // keyed by chatJid
const activeGrants = new Map<string, MountGrant>(); // keyed by grant id
const revokeTimers = new Map<string, NodeJS.Timeout>(); // keyed by grant id

function expandPath(p: string): string {
  if (p.startsWith('~/')) return path.join(os.homedir(), p.slice(2));
  if (p === '~') return os.homedir();
  return path.resolve(p);
}

function saveGrants(): void {
  const grants = [...activeGrants.values()];
  fs.writeFileSync(GRANTS_FILE, JSON.stringify(grants, null, 2));
}

function loadGrants(): MountGrant[] {
  try {
    if (fs.existsSync(GRANTS_FILE)) {
      return JSON.parse(fs.readFileSync(GRANTS_FILE, 'utf-8'));
    }
  } catch (err) {
    logger.warn({ err }, 'Failed to load mount grants file');
  }
  return [];
}

function addAllowedRoot(hostPath: string): void {
  const resolved = expandPath(hostPath);
  let allowlist: MountAllowlist;

  try {
    if (fs.existsSync(MOUNT_ALLOWLIST_PATH)) {
      allowlist = JSON.parse(fs.readFileSync(MOUNT_ALLOWLIST_PATH, 'utf-8'));
    } else {
      allowlist = { allowedRoots: [], blockedPatterns: [], nonMainReadOnly: true };
    }
  } catch {
    allowlist = { allowedRoots: [], blockedPatterns: [], nonMainReadOnly: true };
  }

  // Don't add duplicates
  if (!allowlist.allowedRoots.some((r) => expandPath(r.path) === resolved)) {
    allowlist.allowedRoots.push({
      path: hostPath,
      allowReadWrite: false,
      description: `JIT grant (auto-managed)`,
    });
    fs.writeFileSync(MOUNT_ALLOWLIST_PATH, JSON.stringify(allowlist, null, 2));
    clearMountAllowlistCache();
    logger.info({ hostPath }, 'Added JIT allowed root');
  }
}

function removeAllowedRoot(hostPath: string): void {
  const resolved = expandPath(hostPath);
  try {
    if (!fs.existsSync(MOUNT_ALLOWLIST_PATH)) return;
    const allowlist: MountAllowlist = JSON.parse(
      fs.readFileSync(MOUNT_ALLOWLIST_PATH, 'utf-8'),
    );
    const before = allowlist.allowedRoots.length;
    allowlist.allowedRoots = allowlist.allowedRoots.filter(
      (r) => expandPath(r.path) !== resolved,
    );
    if (allowlist.allowedRoots.length < before) {
      fs.writeFileSync(MOUNT_ALLOWLIST_PATH, JSON.stringify(allowlist, null, 2));
      clearMountAllowlistCache();
      logger.info({ hostPath }, 'Removed JIT allowed root');
    }
  } catch (err) {
    logger.warn({ err, hostPath }, 'Failed to remove allowed root');
  }
}

function revokeGrant(grantId: string): void {
  const grant = activeGrants.get(grantId);
  if (!grant) return;

  removeAllowedRoot(grant.hostPath);
  grant.status = 'expired';
  activeGrants.delete(grantId);
  const timer = revokeTimers.get(grantId);
  if (timer) {
    clearTimeout(timer);
    revokeTimers.delete(grantId);
  }
  saveGrants();
  logger.info(
    { grantId, hostPath: grant.hostPath },
    'Mount grant expired and revoked',
  );
}

/**
 * Send a message to the agent's IPC input directory.
 */
function sendIpcMessage(groupFolder: string, text: string): void {
  const inputDir = path.join(resolveGroupIpcPath(groupFolder), 'input');
  fs.mkdirSync(inputDir, { recursive: true });
  const filename = `${Date.now()}-mount-${Math.random().toString(36).slice(2, 6)}.json`;
  fs.writeFileSync(
    path.join(inputDir, filename),
    JSON.stringify({ type: 'message', text }),
  );
}

// --- Public API ---

/**
 * Handle a mount request from an agent. Stores as pending and sends
 * an approval prompt to the user.
 */
export function handleMountRequest(
  grant: MountGrant,
  sendMessage: (jid: string, text: string) => Promise<void>,
): void {
  pendingGrants.set(grant.chatJid, grant);

  const readOnly = grant.readonly ? 'read-only' : 'read-write';
  const reason = grant.reason ? `\nReason: "${grant.reason}"` : '';
  const msg =
    `Mount request: ${grant.hostPath} (${readOnly}, ${DEFAULT_DURATION_MINUTES} min)` +
    reason +
    `\nReply yes to approve, no to deny. (yes 60 = 60 min)`;

  sendMessage(grant.chatJid, msg).catch((err) =>
    logger.error({ err }, 'Failed to send mount approval prompt'),
  );

  logger.info(
    { grantId: grant.id, hostPath: grant.hostPath, chatJid: grant.chatJid },
    'Mount request pending user approval',
  );
}

/**
 * Check if an inbound message is an approval/denial for a pending mount.
 * Returns true if the message was consumed (don't process further).
 */
export function checkMountApproval(
  chatJid: string,
  content: string,
  sendMessage: (jid: string, text: string) => Promise<void>,
): boolean {
  const grant = pendingGrants.get(chatJid);
  if (!grant) return false;

  const trimmed = content.trim().toLowerCase();
  const approveMatch = trimmed.match(/^(yes|approve|y)\b\s*(\d+)?/);
  const denyMatch = trimmed.match(/^(no|deny|n)\b/);

  if (!approveMatch && !denyMatch) return false;

  pendingGrants.delete(chatJid);

  if (denyMatch) {
    grant.status = 'expired';
    sendIpcMessage(
      grant.groupFolder,
      `[SYSTEM] Mount request for ${grant.hostPath} was denied by the user.`,
    );
    sendMessage(chatJid, `Mount request denied.`).catch(() => {});
    logger.info({ grantId: grant.id }, 'Mount request denied');
    return true;
  }

  // Approve
  const durationMinutes = approveMatch![2]
    ? parseInt(approveMatch![2], 10)
    : DEFAULT_DURATION_MINUTES;

  grant.status = 'active';
  grant.durationMinutes = durationMinutes;
  grant.approvedAt = new Date().toISOString();
  grant.expiresAt = new Date(
    Date.now() + durationMinutes * 60_000,
  ).toISOString();
  grant.hostPath = expandPath(grant.hostPath);

  // Update allowlist and activate
  addAllowedRoot(grant.hostPath);
  activeGrants.set(grant.id, grant);
  saveGrants();

  // Set auto-revoke timer
  const timer = setTimeout(() => revokeGrant(grant.id), durationMinutes * 60_000);
  revokeTimers.set(grant.id, timer);

  // Notify the agent
  sendIpcMessage(
    grant.groupFolder,
    `[SYSTEM] Mount approved: ${grant.hostPath} is now available. ` +
      `Use a mount_task IPC command with grantId "${grant.id}" and a prompt describing what to do with the files. ` +
      `Access expires in ${durationMinutes} minutes.`,
  );

  sendMessage(
    chatJid,
    `Mount approved: ${grant.hostPath} for ${durationMinutes} minutes.`,
  ).catch(() => {});

  logger.info(
    { grantId: grant.id, hostPath: grant.hostPath, durationMinutes },
    'Mount grant approved',
  );

  return true;
}

/**
 * Execute a file task using a mount subagent.
 * Returns the subagent's output.
 */
export async function executeMountTask(
  grantId: string,
  prompt: string,
  sourceGroup: string,
  chatJid: string,
  sendMessage: (jid: string, text: string) => Promise<void>,
): Promise<void> {
  const grant = activeGrants.get(grantId);
  if (!grant || grant.status !== 'active') {
    sendIpcMessage(
      sourceGroup,
      `[SYSTEM] Mount task failed: grant "${grantId}" is not active or has expired.`,
    );
    return;
  }

  if (grant.expiresAt && new Date(grant.expiresAt) < new Date()) {
    revokeGrant(grantId);
    sendIpcMessage(
      sourceGroup,
      `[SYSTEM] Mount task failed: grant has expired.`,
    );
    return;
  }

  logger.info({ grantId, prompt: prompt.slice(0, 100) }, 'Running mount subagent');

  const result = await runMountSubagent(grant, prompt, sourceGroup);

  // Send result back to the main agent via IPC
  sendIpcMessage(
    sourceGroup,
    `[SYSTEM] Mount task result for ${grant.containerPath}:\n${result}`,
  );
}

/**
 * Restore active grants from disk on startup.
 * Revokes expired ones, sets timers for still-active ones.
 */
export function restoreMountGrants(): void {
  const grants = loadGrants();
  const now = Date.now();

  for (const grant of grants) {
    if (grant.status !== 'active') continue;

    const expiresAt = grant.expiresAt ? new Date(grant.expiresAt).getTime() : 0;
    if (expiresAt <= now) {
      // Expired while we were down — clean up
      removeAllowedRoot(grant.hostPath);
      logger.info(
        { grantId: grant.id, hostPath: grant.hostPath },
        'Revoked expired mount grant on startup',
      );
    } else {
      // Still active — restore timer
      activeGrants.set(grant.id, grant);
      const remaining = expiresAt - now;
      const timer = setTimeout(() => revokeGrant(grant.id), remaining);
      revokeTimers.set(grant.id, timer);
      logger.info(
        { grantId: grant.id, hostPath: grant.hostPath, remainingMs: remaining },
        'Restored active mount grant',
      );
    }
  }

  // Save cleaned-up state
  saveGrants();
}
