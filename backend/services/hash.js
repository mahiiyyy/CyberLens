import { createHash } from "node:crypto";
export const sha256Hex = buf => createHash("sha256").update(buf).digest("hex");
