import { getConnInfo } from "hono/cloudflare-workers";
import { Entry, validateEntry } from "./entry";
import { Hono } from "hono";

type Bindings = { DB: D1Database };

const app = new Hono<{ Bindings: Bindings }>();

app.get("/addr", (c) => {
  const addr = getConnInfo(c).remote.address;
  if (!addr) return c.text("Could not determine remote address", 500);

  return c.text(addr);
});

app.post("/", async (c) => {
  const e: Entry = await c.req.json();

  // Validate Entry
  const validationError = await validateEntry(e);
  if (validationError) return c.json({ error: validationError }, 400);

  // Check for existing newer entry
  const existing = await c.env.DB.prepare("SELECT 1 FROM Entries WHERE masterKey = ? AND memberKey = ? AND bodyTimestamp> ? LIMIT 1")
    .bind(e.masterKey, e.member.key, e.body.timestamp)
    .first();

  if (existing) return c.json({ error: "Newer entry already exists" }, 400);

  // Save and replace Entry
  try {
    await c.env.DB.batch([
      c.env.DB.prepare("DELETE FROM Entries WHERE masterKey = ? AND memberKey = ?").bind(e.masterKey, e.member.key),
      c.env.DB.prepare(
        "INSERT INTO Entries (masterKey, memberKey, memberMetadata, memberSignature, bodyData, bodyTimestamp, bodySignature) VALUES (?, ?, ?, ?, ?, ?, ?)"
      ).bind(e.masterKey, e.member.key, e.member.metadata, e.member.signature, e.body.data, e.body.timestamp, e.body.signature),
    ]);
  } catch {
    return c.json({ error: "Failed to update database" }, 500);
  }

  // Fetch all other entries for this master key, excluding the current key
  const query = await c.env.DB.prepare(
    "SELECT memberKey, memberMetadata, memberSignature, bodyData, bodyTimestamp, bodySignature FROM Entries WHERE masterKey = ? AND memberKey != ?"
  )
    .bind(e.masterKey, e.member.key)
    .all();

  if (query.error) return c.json({ error: "Failed to query database" }, 500);

  return c.json(
    query.results.map((e) => ({
      member: {
        key: e.memberKey,
        metadata: e.memberMetadata,
        signature: e.memberSignature,
      },
      body: {
        data: e.bodyData,
        timestamp: e.bodyTimestamp,
        signature: e.bodySignature,
      },
    }))
  );
});

export default {
  fetch: app.fetch,
  async scheduled(_: ScheduledController, env: Bindings, ctx: ExecutionContext) {
    console.log("Cleaning up old entries...");
    ctx.waitUntil(
      env.DB.prepare("DELETE FROM Entries WHERE timestamp < ?")
        .bind(Date.now() - 30 * 60 * 1000)
        .run()
    );
  },
};
