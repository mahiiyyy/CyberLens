import { pool } from "../db/pool.js";

/**
 * Append an audit record. Metadata must describe *what happened*, never contain email content,
 * credentials, API keys or raw indicator payloads. Pass a pg client to join a transaction.
 */
export async function audit(userId, action, entity, entityId = null, metadata = {}, db = pool) {
  await db.query(
    "INSERT INTO audit_logs(user_id,action,entity,entity_id,metadata) VALUES($1,$2,$3,$4,$5)",
    [userId, action, entity, entityId == null ? null : String(entityId), JSON.stringify(metadata)]
  );
}
