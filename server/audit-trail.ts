import { db } from "./db";
import { certifications, users, agentViolations } from "@shared/schema";
import { eq, and, inArray, sql } from "drizzle-orm";

export const VIOLATION_GAP_THRESHOLD_MS = 30 * 60 * 1000;

export interface AuditTrailError {
  status: number;
  error: string;
}

function formatProofEntry(proof: any, role: string) {
  const m = (proof.metadata || {}) as Record<string, any>;
  return {
    role,
    proof_id: proof.id,
    file_hash: proof.fileHash,
    filename: proof.fileName,
    action_type: m.action_type || m.type || "unknown",
    blockchain_status: proof.blockchainStatus,
    transaction_hash: proof.transactionHash,
    transaction_url: proof.transactionUrl,
    certified_at: proof.createdAt,
    verify_url: `https://xproof.app/proof/${proof.id}`,
    explorer_url: proof.transactionUrl,
    metadata: {
      sigil_agent_id: m.sigil_agent_id || null,
      sigil_profile: m.sigil_profile || null,
      post_id: m.post_id || null,
      target_author: m.target_author || m.targetAuthor || null,
      content_preview: m.content_preview || null,
      decision_chain: m.decision_chain || null,
      prompt_hash: m.prompt_hash || null,
      trigger_content_hash: m.trigger_content_hash || null,
      rules_applied: m.rules_applied || null,
      content_hash: m.content_hash || null,
    },
  };
}

export async function reconstructAuditTrail(wallet: string, proofId: string) {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  if (!proofId || !uuidRegex.test(proofId)) {
    throw { status: 400, error: "Invalid proof_id format — expected UUID" } as AuditTrailError;
  }

  const [user] = await db
    .select({ id: users.id, isPublicProfile: users.isPublicProfile, walletAddress: users.walletAddress, agentName: users.agentName })
    .from(users)
    .where(eq(users.walletAddress, wallet));

  if (!user || !user.isPublicProfile) {
    throw { status: 404, error: "Agent profile not found or not public" } as AuditTrailError;
  }

  const [contestedProof] = await db
    .select()
    .from(certifications)
    .where(and(eq(certifications.id, proofId), eq(certifications.userId, user.id)));

  if (!contestedProof) {
    throw { status: 404, error: "Proof not found for this agent" } as AuditTrailError;
  }

  const meta = (contestedProof.metadata || {}) as Record<string, any>;
  const actionType = meta.action_type || meta.type || null;
  const isHeartbeat = actionType === "heartbeat" || meta.type === "heartbeat";
  const isReasoning = typeof actionType === "string" && actionType.endsWith("_reasoning");
  const isAction = !isHeartbeat && !isReasoning && actionType;

  const timeline: any[] = [];
  let sessionHeartbeat: any = null;
  let pairedProof: any = null;

  if (isHeartbeat) {
    sessionHeartbeat = formatProofEntry(contestedProof, "heartbeat");
    const actionProofs = meta.action_proofs || meta.actions || [];
    if (actionProofs.length > 0) {
      const actionIds = actionProofs.map((a: any) => a.proof_id || a.why_proof_id || a.what_proof_id).filter(Boolean);
      if (actionIds.length > 0) {
        const actionCerts = await db
          .select()
          .from(certifications)
          .where(and(eq(certifications.userId, user.id), inArray(certifications.id, actionIds)));
        const sorted = actionCerts.sort((a, b) => new Date(a.createdAt!).getTime() - new Date(b.createdAt!).getTime());
        for (const cert of sorted) {
          const cm = (cert.metadata || {}) as Record<string, any>;
          const at = cm.action_type || "";
          const role = at.endsWith("_reasoning") ? "WHY" : "WHAT";
          timeline.push(formatProofEntry(cert, role));
        }
      }
    }
  } else {
    const postId = meta.post_id || null;
    const targetAuthor = meta.target_author || meta.targetAuthor || null;

    if (isReasoning && postId) {
      const baseType = actionType!.replace(/_reasoning$/, "");
      timeline.push(formatProofEntry(contestedProof, "WHY"));

      const pairResults = await db.execute(sql`
        SELECT * FROM certifications
        WHERE user_id = ${user.id}
          AND blockchain_status = 'confirmed'
          AND metadata->>'action_type' = ${baseType}
          AND metadata->>'post_id' = ${postId}
          AND (
            (${targetAuthor}::text IS NULL AND metadata->>'target_author' IS NULL AND metadata->>'targetAuthor' IS NULL)
            OR metadata->>'target_author' = ${targetAuthor}::text
            OR metadata->>'targetAuthor' = ${targetAuthor}::text
          )
          AND created_at > ${contestedProof.createdAt}
        ORDER BY created_at ASC
        LIMIT 1
      `);
      if (pairResults.rows.length > 0) {
        const row = pairResults.rows[0] as any;
        pairedProof = { id: row.id, fileHash: row.file_hash, fileName: row.file_name, blockchainStatus: row.blockchain_status, transactionHash: row.transaction_hash, transactionUrl: row.transaction_url, createdAt: row.created_at, metadata: row.metadata };
        timeline.push(formatProofEntry(pairedProof, "WHAT"));
      }
    } else if (isAction && postId) {
      const reasoningType = actionType + "_reasoning";

      const pairResults = await db.execute(sql`
        SELECT * FROM certifications
        WHERE user_id = ${user.id}
          AND blockchain_status = 'confirmed'
          AND metadata->>'action_type' = ${reasoningType}
          AND metadata->>'post_id' = ${postId}
          AND (
            (${targetAuthor}::text IS NULL AND metadata->>'target_author' IS NULL AND metadata->>'targetAuthor' IS NULL)
            OR metadata->>'target_author' = ${targetAuthor}::text
            OR metadata->>'targetAuthor' = ${targetAuthor}::text
          )
          AND created_at < ${contestedProof.createdAt}
        ORDER BY created_at DESC
        LIMIT 1
      `);
      if (pairResults.rows.length > 0) {
        const row = pairResults.rows[0] as any;
        pairedProof = { id: row.id, fileHash: row.file_hash, fileName: row.file_name, blockchainStatus: row.blockchain_status, transactionHash: row.transaction_hash, transactionUrl: row.transaction_url, createdAt: row.created_at, metadata: row.metadata };
        timeline.push(formatProofEntry(pairedProof, "WHY"));
      }
      timeline.push(formatProofEntry(contestedProof, "WHAT"));
    } else {
      timeline.push(formatProofEntry(contestedProof, "contested"));
    }

    const allProofIds = timeline.map((t) => t.proof_id);
    const heartbeatCandidates = await db.execute(sql`
      SELECT id, file_name, file_hash, blockchain_status, transaction_hash,
             metadata, created_at, file_type, user_id
      FROM certifications
      WHERE user_id = ${user.id}
        AND blockchain_status = 'confirmed'
        AND (metadata->>'type' = 'heartbeat' OR metadata->>'action_type' = 'heartbeat')
        AND created_at >= ${contestedProof.createdAt}
      ORDER BY created_at ASC
      LIMIT 10
    `);

    for (const hb of heartbeatCandidates.rows as any[]) {
      const hbMeta = hb.metadata || {};
      const actionProofs = hbMeta.action_proofs || hbMeta.actions || [];
      const proofIdsInHb = actionProofs.map((a: any) => a.proof_id);
      if (allProofIds.some((id: string) => proofIdsInHb.includes(id))) {
        sessionHeartbeat = {
          role: "heartbeat",
          proof_id: hb.id,
          filename: hb.file_name,
          blockchain_status: hb.blockchain_status,
          transaction_hash: hb.transaction_hash,
          certified_at: hb.created_at,
          verify_url: `https://xproof.app/proof/${hb.id}`,
          session_summary: hbMeta.summary || null,
          session_timestamp: hbMeta.timestamp || null,
          total_actions_in_session: actionProofs.length,
        };
        break;
      }
    }
  }

  timeline.sort((a, b) => new Date(a.certified_at).getTime() - new Date(b.certified_at).getTime());

  const whyEntry = timeline.find((t) => t.role === "WHY");
  const whatEntry = timeline.find((t) => t.role === "WHAT");
  let intentPrecededExecution: boolean | null = null;
  if (whyEntry && whatEntry) {
    intentPrecededExecution = new Date(whyEntry.certified_at).getTime() < new Date(whatEntry.certified_at).getTime();
  }

  const result = {
    agent: {
      wallet: user.walletAddress,
      name: user.agentName || null,
      sigil_id: meta.sigil_agent_id || timeline[0]?.metadata?.sigil_agent_id || null,
    },
    contested_proof_id: proofId,
    report_generated_at: new Date().toISOString(),
    verification: {
      intent_preceded_execution: intentPrecededExecution,
      why_certified: !!whyEntry,
      what_certified: !!whatEntry,
      session_anchored: !!sessionHeartbeat,
      all_confirmed: timeline.every((t) => t.blockchain_status === "confirmed"),
    },
    timeline,
    session: sessionHeartbeat,
    violations_created: 0,
  };

  return result;
}

export async function detectAndRecordViolations(
  wallet: string,
  proofId: string,
  verification: { intent_preceded_execution: boolean | null; why_certified: boolean; what_certified: boolean },
  timeline: any[],
): Promise<number> {
  const anomalies: { type: "fault" | "breach"; reason: string; autoConfirm: boolean }[] = [];

  if (verification.intent_preceded_execution === false) {
    anomalies.push({
      type: "fault",
      reason: "WHAT was certified before WHY — execution preceded intent declaration",
      autoConfirm: true,
    });
  }

  if (verification.why_certified && !verification.what_certified) {
    const whyEntry = timeline.find((t: any) => t.role === "WHY");
    if (whyEntry) {
      const whyTime = new Date(whyEntry.certified_at).getTime();
      const now = Date.now();
      if (now - whyTime > VIOLATION_GAP_THRESHOLD_MS) {
        anomalies.push({
          type: "fault",
          reason: `WHY certified but no matching WHAT found after ${Math.round(VIOLATION_GAP_THRESHOLD_MS / 60000)} minutes`,
          autoConfirm: true,
        });
      }
    }
  }

  if (!verification.why_certified && verification.what_certified) {
    anomalies.push({
      type: "fault",
      reason: "WHAT certified without any WHY — action executed without prior intent declaration",
      autoConfirm: true,
    });
  }

  let created = 0;
  for (const anomaly of anomalies) {
    const existing = await db.execute(sql`
      SELECT id FROM agent_violations
      WHERE wallet_address = ${wallet}
        AND proof_id = ${proofId}
        AND type = ${anomaly.type}
        AND reason = ${anomaly.reason}
      LIMIT 1
    `);
    if (existing.rows.length > 0) continue;

    const status = anomaly.autoConfirm ? "confirmed" : "proposed";
    const confirmedAt = anomaly.autoConfirm ? new Date() : null;

    await db.insert(agentViolations).values({
      walletAddress: wallet,
      proofId,
      type: anomaly.type,
      status,
      reason: anomaly.reason,
      autoConfirmed: anomaly.autoConfirm,
      confirmedAt,
    });
    created++;
  }

  return created;
}
