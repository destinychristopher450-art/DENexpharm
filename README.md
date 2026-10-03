# DENexPharm 7.1.0 — deployment package

This is the consolidated DENexPharm package prepared from the latest project files and deployment fixes.

## Included
- `server.js` — production Express backend, PostgreSQL support, JSON fallback, JWT authentication, question access, XP/scores, leaderboard, admin question tools and Paystack Premium verification/webhook.
- `public/index.html` — browser frontend.
- `question.json` — DENexPharm question bank.
- `schema.sql` — PostgreSQL schema plus migration-safe columns for older databases.
- `data/db.json` — empty local fallback database.
- `package.json` — Node dependencies and Render start command.
- `.env.example` — required environment-variable template.

## Render deployment
1. Extract the ZIP.
2. Upload/push the whole folder to the GitHub repository used by the Render Web Service.
3. In Render, use **Web Service** with build command `npm install` and start command `npm start`.
4. Set Node to a supported version (Node 18+; Node 20/22 is recommended).
5. Connect a PostgreSQL database and copy its internal `DATABASE_URL` into the Web Service environment.
6. Add the variables from `.env.example`.
7. For real Premium payments, use a Paystack **live** secret key beginning with `sk_live_`.
8. Set Paystack callback URL to `https://YOUR-RENDER-DOMAIN/api/payments/callback`.
9. Set the Paystack webhook URL to `https://YOUR-RENDER-DOMAIN/api/payments/webhook`.
10. After deploy, open `/api/health`. It should return JSON with `ok: true` and a question count.

## Important
This package is a Node/Express server application. It is intended to run as a Node Web Service (such as Render). A Cloudflare Workers/Pages URL cannot directly run this Express server simply by uploading these files; Cloudflare can be used as a frontend/proxy layer while the Node backend remains on a Node-compatible host.

## Premium price
The backend controls the Premium price and currency. The current package defaults are `5000 NGN`. The browser cannot override the payment amount or currency. Production payment activation requires server-side Paystack verification and the matching internal payment record.

## Existing PostgreSQL database
Do not delete the existing database. `schema.sql` uses `ADD COLUMN IF NOT EXISTS` for the user fields that caused the earlier `xp`/schema mismatch. The latest server also contains the audit-log ID-type repair for older databases where `audit_logs.user_id` was TEXT while `users.id` was INTEGER.
