# DENexpharm v4.0.0

DENexpharm is a pharmacy-learning and quiz MVP designed for pharmacy students, with Nigeria support and a structure that can be expanded for international users.

## Included in this package

- `server.js` — Express backend and API
- `package.json` — Node.js dependencies and start command
- `public/index.html` — main web application
- `public/manifest.json` — web-app manifest
- `public/404.html` — fallback page
- `data/db.json` — local MVP data store
- `schema.sql` — PostgreSQL database schema for future/production use
- `.env.example` — environment-variable template
- `render.yaml` — Render deployment configuration
- `.gitignore` — files that should not be committed

## Run locally

Requirements: Node.js 18 or newer.

```bash
npm install
npm start
```

Then open the local address shown by the server (normally `http://localhost:3000`).

## Deploy to Render

The current project is an Express/Node.js application, so deploy the complete project as a **Render Web Service**, not as a Cloudflare Pages static site.

1. Extract this ZIP.
2. Create a GitHub repository.
3. Upload the contents of the `DENexpharm` folder to the repository.
4. In Render, choose **New → Web Service** and connect the GitHub repository.
5. Build command: `npm install`
6. Start command: `npm start`
7. Add the environment variables required for the services you enable.
8. Deploy and open the Render URL provided by Render.

`render.yaml` is included as a reference for the Render deployment configuration.

## Environment variables

Copy `.env.example` to `.env` when running locally and fill in the values you actually use. Never commit real secret keys to GitHub.

Typical variables include:

- `PORT` — server port; Render supplies its own port automatically.
- `FRONTEND_ORIGIN` — allowed frontend origin when using a separate frontend.
- `DATABASE_URL` — PostgreSQL connection string when using PostgreSQL.
- `SESSION_SECRET` — long random secret for sessions.
- `PAYSTACK_SECRET_KEY` — Paystack secret key if payment features are enabled.
- `PAYSTACK_PUBLIC_KEY` — Paystack public key if payment features are enabled.

## Important deployment note

The JSON data store is suitable for an MVP/demo. For durable production data, use PostgreSQL (for example, Render PostgreSQL, Neon, or Supabase) and configure `DATABASE_URL` according to the backend implementation.

Do not place payment secret keys or other private credentials inside `public/index.html`, GitHub, or screenshots.

## Cloudflare

Cloudflare Pages is suitable for a static frontend. This package contains a Node/Express backend, so the complete package should be deployed to a Node-compatible host such as Render unless the backend is separately rewritten for Cloudflare Workers.

## Project goal

DENexpharm is intended to grow into a larger pharmacy-learning platform with question banks, practice and exam modes, explanations, progress tracking, leaderboards, challenges, pharmacy calculations, reference resources, language assistance, and optional premium features.

## License / content

This MVP is a project starter. Add only content and reference material that you have permission to distribute. Do not copy copyrighted pharmacopoeia monographs, textbooks, or question banks without the appropriate rights.
