import { verifySignature } from "./crypto";

export type Member = {
  key: string;
  metadata: string;
  signature: string;
};

export type Body = {
  data: string;
  timestamp: number;
  signature: string;
};

export type Entry = {
  masterKey: string;
  member: Member;
  body: Body;
};

// Validates an Entry object. Returns an error message string on failure, or null on success.
export const validateEntry = async (e: Entry): Promise<string | null> => {
  const now = Date.now();
  if (!e.body.timestamp || e.body.timestamp < now - 5000 || e.body.timestamp > now) return "Invalid Timestamp";

  if (!e.masterKey) return "masterKey is required";
  if (!e.member?.key) return "member.key is required";
  if (!e.member?.signature) return "member.signature is required";
  if (!e.body?.signature) return "body.signature is required";

  const memberData = e.member.key.toString() + e.member.metadata.toString();
  const memberErr = await verifySignature(e.masterKey, e.member.signature, memberData);
  if (memberErr) return `Invalid memberSignature: ${memberErr}`;

  const bodyData = e.member.signature.toString() + e.body.data.toString() + e.body.timestamp.toString();
  const bodyErr = await verifySignature(e.masterKey, e.body.signature, bodyData);
  if (bodyErr) return `Invalid bodySignature: ${bodyErr}`;

  return null;
};
