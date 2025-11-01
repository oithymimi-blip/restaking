# USDT Approval Suite — Referrals + Wallet Login + Countdown

This build adds:
- **Wallet login (signature)** → Navbar "Login" button.
- **Referral codes** (4–7 chars) generated on first login/first approval.
- Store `?ref=CODE` on visit; when the referred wallet approves, the referrer gets +1 (once per referee wallet).
- Show **referral link + total referrals** to logged‑in users (navbar mini badge + card).
- **Countdown section** styled like your reference. Configure end time via `STAKING_END_TS` (unix seconds).

## Run
```bash
npm install
cp .env.example .env
npm run dev
# user:  http://localhost:5173/
# admin: http://localhost:5173/admin  (login: admin / admin123)
```
Change creds & end time in `.env` as needed.
# restaking
# restaking
