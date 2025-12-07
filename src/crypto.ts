// Decodes a base64 string into a Uint8Array. Returns null on failure.
const b64Decode = (data: string) => {
  try {
    return Uint8Array.from(atob(data), (c) => c.charCodeAt(0));
  } catch {
    return null;
  }
};

// Imports a raw Ed25519 public key for verification. Returns a CryptoKey or null on failure.
const importKey = async (key: Uint8Array) => {
  try {
    return await crypto.subtle.importKey("raw", key, { name: "Ed25519" }, false, ["verify"]);
  } catch {
    return null;
  }
};

// Verifies an Ed25519 signature. Returns an error message string on failure, or null on success.
export const verifySignature = async (key: string, sig: string, body: string) => {
  const keyBytes = b64Decode(key);
  if (!keyBytes) return "Failed to decode key";

  const keyData = await importKey(keyBytes);
  if (!keyData) return "Failed to import key";

  const sigBytes = b64Decode(sig);
  if (!sigBytes) return "Failed to decode signature";

  const bodyBytes = Uint8Array.from(body, (c) => c.charCodeAt(0));
  if (!bodyBytes) return "Failed to parse body";

  try {
    if (!crypto.subtle.verify("Ed25519", keyData, sigBytes, bodyBytes)) return "Invalid signature";
  } catch {
    return "Failed to verify signature";
  }

  return null;
};
