import test from "node:test";
import assert from "node:assert/strict";
import express from "express";
import { randomUUID } from "node:crypto";
import bcrypt from "bcryptjs";
import auth from "../routes/auth.js";
import { pool } from "../db/pool.js";

test("account lifecycle against a disposable PostgreSQL database", async () => {
  assert.equal(process.env.CYBERLENS_TEST_DB, "1", "Use only a disposable test database");
  assert.ok(process.env.DATABASE_URL);
  assert.ok(process.env.JWT_SECRET?.length >= 32);
  const app = express();
  app.use(express.json());
  app.use("/auth", auth);
  app.use((err, req, res, next) => res.status(500).json({ error: "Test server error" }));
  const server = app.listen(0, "127.0.0.1");
  await new Promise(resolve => server.once("listening", resolve));
  const base = "http://127.0.0.1:" + server.address().port + "/auth";
  const email = randomUUID() + "@example.invalid";
  const password = "Test-only-password-729";
  const request = (path, body, cookie) => fetch(base + path, {
    method: body === undefined ? "GET" : "POST",
    headers: { "Content-Type": "application/json", ...(cookie ? { Cookie: cookie } : {}) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) })
  });
  try {
    assert.equal((await request("/me")).status, 401);
    assert.equal((await request("/register", {email, password:"short"})).status, 400);
    const registered = await request("/register", { email, password });
    assert.equal(registered.status, 200);
    const session = registered.headers.get("set-cookie");
    assert.match(session, /HttpOnly/i);
    assert.match(session, /SameSite=Lax/i);
    const cookie = session.split(";")[0];
    const data = await registered.json();
    assert.equal(data.user.email, email);
    assert.equal(data.user.role, "ANALYST");
    assert.equal(data.user.password_hash, undefined);
    const row = (await pool.query("SELECT password_hash FROM users WHERE email=$1", [email])).rows[0];
    assert.notEqual(row.password_hash, password);
    assert.equal(await bcrypt.compare(password, row.password_hash), true);
    assert.equal((await request("/register", {email,password})).status, 409);
    assert.equal((await request("/login", {email,password:"incorrect-password"})).status, 401);
    const login = await request("/login", {email,password,remember:true});
    assert.equal(login.status, 200);
    assert.match(login.headers.get("set-cookie"), /Max-Age=604800/i);
    const me = await request("/me", undefined, cookie);
    assert.equal(me.status, 200);
    assert.equal((await me.json()).user.id, data.user.id);
    const logout = await request("/logout", {}, cookie);
    assert.equal(logout.status, 200);
    assert.match(logout.headers.get("set-cookie"), /Expires=/i);
  } finally {
    await pool.query("DELETE FROM users WHERE email=$1", [email]);
    await new Promise(resolve => server.close(resolve));
    await pool.end();
  }
});
