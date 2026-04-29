import Fastify from "fastify";
import fastifyJwt from "@fastify/jwt";
import multipart from "@fastify/multipart";
import pg from "pg";
import crypto from "node:crypto";
import { createReadStream, createWriteStream, mkdirSync } from "fs";
import { pipeline } from "stream/promises";
import AdmZip from 'adm-zip';
import fs from 'fs';
import path from 'path';

const { Client } = pg;
const db = new Client({
  connectionString: process.env.DATABASE_URL || "postgresql://postgres:ahbap@localhost/library_dev",
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});
await db.connect();

// ── VERİTABANI ŞEMALARI ──
await db.query(`
  CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username TEXT NOT NULL UNIQUE,
    client_key TEXT NOT NULL
  )
`);
await db.query(`
  CREATE TABLE IF NOT EXISTS books (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username TEXT NOT NULL,
    original_name TEXT NOT NULL,
    filename TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now()
  )
`);
await db.query(`
  CREATE TABLE IF NOT EXISTS notes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username TEXT NOT NULL,
    book_id UUID REFERENCES books(id) ON DELETE SET NULL,
    title TEXT NOT NULL DEFAULT 'Yeni Not',
    content TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
  )
`);
await db.query(`
  CREATE TABLE IF NOT EXISTS highlights (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username TEXT NOT NULL,
    book_id UUID REFERENCES books(id) ON DELETE CASCADE,
    cfi TEXT,
    page_num INT,
    selected_text TEXT NOT NULL,
    color TEXT NOT NULL DEFAULT '#ffeb3b',
    created_at TIMESTAMPTZ DEFAULT now()
  )
`);
await db.query(`
  CREATE TABLE IF NOT EXISTS todos_matrix (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username TEXT NOT NULL,
    label TEXT NOT NULL,
    days JSONB DEFAULT '[false,false,false,false,false,false,false]',
    created_at TIMESTAMPTZ DEFAULT now()
  )
`);

// YENİ: VİZYON PANOSU / AJANDA TABLOSU
await db.query(`
  CREATE TABLE IF NOT EXISTS plans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username TEXT NOT NULL,
    type TEXT NOT NULL,
    content TEXT NOT NULL,
    is_completed BOOLEAN DEFAULT false,
    target_date DATE,
    image_url TEXT,
    created_at TIMESTAMPTZ DEFAULT now()
  )
`);

// 👇👇 BU SATIRI YENİ EKLEDİK: Eğer önceden tablo oluştuysa resim sütununu zorla ekler! 👇👇
await db.query(`ALTER TABLE plans ADD COLUMN IF NOT EXISTS image_url TEXT`);

console.log("Veritabanı bağlantısı ve tablolar hazır ✓");

mkdirSync("./uploads", { recursive: true });

const sessions = new Map();
const app = Fastify({ logger: false });

app.addHook("onRequest", (req, reply, done) => {
  reply.header("Access-Control-Allow-Origin", "*");
  reply.header("Access-Control-Allow-Methods", "POST, GET, PUT, DELETE, OPTIONS");
  reply.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
  if (req.method === "OPTIONS") return reply.send();
  done();
});

await app.register(fastifyJwt, { secret: "gizli-anahtar-degistir" });
await app.register(multipart, { limits: { fileSize: 500 * 1024 * 1024 } });

// ── AUTH (KİMLİK) ──
app.post("/auth/register", async (req: any, reply) => {
  const { username, clientKey } = req.body;
  try {
    await db.query(`INSERT INTO users (username, client_key) VALUES ($1, $2)`, [username, clientKey]);
    return reply.code(201).send({ ok: true });
  } catch (err: any) {
    if (err.code === "23505") return reply.code(409).send({ error: "Kullanıcı adı alınmış" });
    throw err;
  }
});

app.post("/auth/challenge", async (req: any, reply) => {
  const { username } = req.body;
  const result = await db.query(`SELECT client_key FROM users WHERE username = $1`, [username]);
  if (result.rowCount === 0) return reply.code(401).send({ error: "Geçersiz kimlik" });
  const challenge = crypto.randomUUID();
  sessions.set(challenge, { username, clientKey: result.rows[0].client_key });
  setTimeout(() => sessions.delete(challenge), 30_000);
  return { challenge };
});

app.post("/auth/verify", async (req: any, reply) => {
  const { challenge, proof } = req.body;
  const session = sessions.get(challenge);
  if (!session) return reply.code(401).send({ error: "Oturum süresi doldu" });
  sessions.delete(challenge);
  const expectedProof = crypto.createHash("sha256").update(session.clientKey + challenge).digest("hex");
  if (proof !== expectedProof) return reply.code(401).send({ error: "Şifre Yanlış" });
  const accessToken = app.jwt.sign({ sub: session.username }, { expiresIn: "15m" });
  return { accessToken };
});

// ── KİTAPLAR ──
app.post("/books/upload", async (req: any, reply) => {
  try {
    const data = await req.file();
    if (!data) return reply.code(400).send({ error: "Dosya bulunamadı" });
    const ext = data.filename.split(".").pop();
    const filename = crypto.randomUUID() + "." + ext;
    const filepath = path.join("./uploads", filename);
    await pipeline(data.file, createWriteStream(filepath));
    await db.query(
      `INSERT INTO books (username, original_name, filename) VALUES ($1, $2, $3)`,
      [data.fields.username.value, data.filename, filename],
    );
    return { ok: true, filename };
  } catch (err: any) {
    return reply.code(500).send({ error: err.message });
  }
});

app.get("/books/list/:username", async (req: any) => {
  const { username } = req.params;
  const result = await db.query(`SELECT id, original_name, filename, created_at FROM books WHERE username = $1 ORDER BY created_at DESC`, [username]);
  return result.rows;
});

app.get("/books/file/:filename", async (req: any, reply) => {
  const { filename } = req.params;
  const filepath = path.join("./uploads", filename);
  const ext = filename.split(".").pop();
  const contentType = ext === "pdf" ? "application/pdf" : "application/epub+zip";
  reply.header("Content-Type", contentType);
  return reply.send(createReadStream(filepath));
});

app.get("/books/cover/:id", async (req: any, reply) => {
  const { id } = req.params;
  try {
    const result = await db.query('SELECT * FROM books WHERE id = $1', [id]);
    if (result.rows.length === 0) return reply.code(404).send({ error: 'Kitap bulunamadı' });
    const book = result.rows[0];
    const filePath = path.join('./uploads', book.filename);
    const ext = book.filename.split('.').pop()?.toLowerCase();

    if (ext === 'epub') {
        const zip = new AdmZip(filePath);
        const entries = zip.getEntries();
        const coverEntry = entries.find(e => /cover\.(jpg|jpeg|png|webp)$/i.test(e.entryName));
        if (coverEntry) {
          reply.header('Content-Type', 'image/jpeg');
          return reply.send(coverEntry.getData());
        }
    }
    return reply.code(404).send({ error: 'Kapak bulunamadı' });
  } catch (err) {
    return reply.code(500).send({ error: 'Sunucu hatası' });
  }
});

app.delete("/books/:id", async (req: any, reply) => {
  const { id } = req.params;
  const result = await db.query(`SELECT filename FROM books WHERE id = $1`, [id]);
  if (result.rowCount === 0) return reply.code(404).send({ error: "Kitap bulunamadı" });
  const { filename } = result.rows[0];
  try { fs.unlinkSync(path.join("./uploads", filename)); } catch {}
  await db.query(`DELETE FROM books WHERE id = $1`, [id]);
  return { ok: true };
});

// ── VİZYON / AJANDA RESİM İŞLEMLERİ ──
app.post("/plans/upload-image", async (req: any, reply) => {
  try {
    const data = await req.file();
    if (!data) return reply.code(400).send({ error: "Dosya bulunamadı" });
    const ext = data.filename.split(".").pop();
    const filename = "vision_" + crypto.randomUUID() + "." + ext;
    const filepath = path.join("./uploads", filename);
    await pipeline(data.file, createWriteStream(filepath));
    return { ok: true, filename };
  } catch (err: any) {
    return reply.code(500).send({ error: err.message });
  }
});

app.get("/images/:filename", async (req: any, reply) => {
  const { filename } = req.params;
  const filepath = path.join("./uploads", filename);
  const ext = filename.split(".").pop()?.toLowerCase();
  const mime = ext === 'png' ? 'image/png' : ext === 'webp' ? 'image/webp' : 'image/jpeg';
  reply.header("Content-Type", mime);
  return reply.send(createReadStream(filepath));
});

// ── VİZYON / AJANDA İŞLEMLERİ ──
app.get("/plans/:username/:type", async (req: any) => {
  const { username, type } = req.params;
  const result = await db.query(
    `SELECT * FROM plans WHERE username = $1 AND type = $2 ORDER BY created_at ASC`,
    [username, type]
  );
  return result.rows;
});

app.post("/plans", async (req: any) => {
  const { username, type, content, target_date, image_url } = req.body;
  const result = await db.query(
    `INSERT INTO plans (username, type, content, target_date, image_url) VALUES ($1, $2, $3, $4, $5) RETURNING *`,
    [username, type, content, target_date, image_url]
  );
  return result.rows[0];
});

app.put("/plans/:id", async (req: any) => {
  const { is_completed } = req.body;
  const result = await db.query(
    `UPDATE plans SET is_completed = $1 WHERE id = $2 RETURNING *`,
    [is_completed, req.params.id]
  );
  return result.rows[0];
});

app.delete("/plans/:id", async (req: any) => {
  await db.query(`DELETE FROM plans WHERE id = $1`, [req.params.id]);
  return { ok: true };
});

// ── NOTLAR, VURGULAR VE TODO MATRİS ──
app.get("/notes/:username", async (req: any) => {
  const result = await db.query(`SELECT * FROM notes WHERE username = $1 ORDER BY updated_at DESC`, [req.params.username]);
  return result.rows;
});

app.post("/notes", async (req: any) => {
  const { username, title, content, book_id } = req.body;
  const result = await db.query(`INSERT INTO notes (username, title, content, book_id) VALUES ($1, $2, $3, $4) RETURNING *`, [username, title, content, book_id]);
  return result.rows[0];
});

app.put("/notes/:id", async (req: any) => {
  const { title, content } = req.body;
  const result = await db.query(`UPDATE notes SET title = $1, content = $2, updated_at = now() WHERE id = $3 RETURNING *`, [title, content, req.params.id]);
  return result.rows[0];
});

app.delete("/notes/:id", async (req: any) => {
  await db.query(`DELETE FROM notes WHERE id = $1`, [req.params.id]);
  return { ok: true };
});

app.get("/highlights/:book_id", async (req: any) => {
  const result = await db.query(`SELECT * FROM highlights WHERE book_id = $1 ORDER BY created_at ASC`, [req.params.book_id]);
  return result.rows;
});

app.post("/highlights", async (req: any) => {
  const { username, book_id, cfi, page_num, selected_text, color } = req.body;
  const result = await db.query(
    `INSERT INTO highlights (username, book_id, cfi, page_num, selected_text, color) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
    [username, book_id, cfi || null, page_num || null, selected_text, color || '#ffeb3b']
  );
  return result.rows[0];
});

app.delete("/highlights/:id", async (req: any) => {
  await db.query(`DELETE FROM highlights WHERE id = $1`, [req.params.id]);
  return { ok: true };
});

app.get("/todos/:username", async (req: any) => {
  const result = await db.query(`SELECT * FROM todos_matrix WHERE username = $1 ORDER BY created_at ASC`, [req.params.username]);
  return result.rows;
});

app.post("/todos", async (req: any) => {
  const { username, label, days } = req.body;
  const result = await db.query(
    `INSERT INTO todos_matrix (username, label, days) VALUES ($1, $2, $3) RETURNING *`,
    [username, label, JSON.stringify(days || Array(7).fill(false))]
  );
  return result.rows[0];
});

app.put("/todos/:id", async (req: any) => {
  const { days } = req.body;
  const result = await db.query(
    `UPDATE todos_matrix SET days = $1 WHERE id = $2 RETURNING *`,
    [JSON.stringify(days), req.params.id]
  );
  return result.rows[0];
});

app.delete("/todos/:id", async (req: any) => {
  await db.query(`DELETE FROM todos_matrix WHERE id = $1`, [req.params.id]);
  return { ok: true };
});

app.get("/todos/summary/:username", async (req: any) => {
  const result = await db.query(`SELECT label, days FROM todos_matrix WHERE username = $1`, [req.params.username]);
  let reportStr = "Kullanıcının bu haftaki alışkanlık tablosu:\n";
  result.rows.forEach((t: any) => {
    const doneCount = t.days.filter(Boolean).length;
    reportStr += `- ${t.label}: 7 günün ${doneCount} gününde yapıldı.\n`;
  });
  const prompt = reportStr + "\nBu veriye bakarak kısa, net ve motive edici bir kütüphane asistanı değerlendirmesi yaz.";
  return { summaryPrompt: prompt };
});

app.post("/agent/chat", async (req: any, reply) => {
  const { messages, systemPrompt } = req.body;
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) return reply.code(500).send({ error: "API KEY eksik" });
  try {
    const response = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-api-key": apiKey, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({
        model: "claude-3-haiku-20240307",
        max_tokens: 1024,
        system: systemPrompt || "Sen bir kütüphane asistanısın.",
        messages
      })
    });
    const data = await response.json() as any;
    return { reply: data?.content?.[0]?.text || "Hata oluştu." };
  } catch (err) {
    return reply.code(500).send({ error: "Ajan hatası" });
  }
});

app.listen({ port: 3000, host: '0.0.0.0' }, (err) => {
  if (err) { console.error(err); process.exit(1); }
  console.log("Sunucu çalışıyor → http://localhost:3000");
});