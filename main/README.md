# ⚡ ULTIMATE CTF v6.0 — MySQL Edition

Password analyzer + live leaderboard + admin panel.  
Converted from SQLite3 → MySQL. Ready to deploy anywhere.

---

## 🚀 Quick Deploy Options

### Option A — Railway (EASIEST, free tier available)

Railway gives you both a Node server AND a MySQL database in one place.

1. Go to **https://railway.app** → sign up with GitHub
2. Click **New Project → Deploy from GitHub repo**
3. Push your code to GitHub first (see step below), then select it
4. Railway auto-detects Node.js and runs `npm start`
5. In your project dashboard: click **New → Database → MySQL**
6. Railway auto-injects these env vars — copy them to your service:
   - `MYSQLHOST` → put as `MYSQL_HOST`
   - `MYSQLPORT` → put as `MYSQL_PORT`  
   - `MYSQLUSER` → put as `MYSQL_USER`
   - `MYSQLPASSWORD` → put as `MYSQL_PASSWORD`
   - `MYSQLDATABASE` → put as `MYSQL_DATABASE`
   - `MYSQL_SSL` = `false` (Railway internal network, no SSL needed)
7. Add `ADMIN_PASSWORD=danik2026` in the Variables tab
8. Done — Railway gives you a public URL

---

### Option B — Render (free tier, easy)

1. Go to **https://render.com** → sign up
2. **New → Web Service** → connect your GitHub repo
3. Build command: `npm install`  
   Start command: `npm start`
4. For the database, use **PlanetScale** (free MySQL, see below)
5. Set environment variables in Render dashboard

---

### Option C — Fly.io (more control, generous free tier)

```bash
# Install flyctl
curl -L https://fly.io/install.sh | sh

# In your project folder
fly launch          # follow prompts
fly mysql create    # creates a MySQL instance
fly secrets set MYSQL_HOST=... MYSQL_USER=... MYSQL_PASSWORD=... MYSQL_DATABASE=ctf MYSQL_SSL=true ADMIN_PASSWORD=danik2026
fly deploy
```

---

## 🗄️ Free MySQL Database Providers

You need a MySQL host. Pick one:

| Provider | Free Tier | Notes |
|---|---|---|
| **PlanetScale** | 5GB free | Best for production, requires SSL |
| **Railway** | Included with app | Easiest if using Railway for hosting |
| **Clever Cloud** | 5MB free | Good for small CTF events |
| **Aiven** | 1 service free | Requires SSL |

### PlanetScale Setup (recommended standalone DB)

1. Go to **https://planetscale.com** → sign up
2. Create a new database → name it `ctf`
3. Click **Connect** → choose **Node.js** → copy the credentials
4. Set `MYSQL_SSL=true` in your env vars
5. PlanetScale uses branch-based schema — just run the app and it auto-creates tables

---

## 📁 Push to GitHub (needed for Railway/Render)

```bash
git init
git add .
git commit -m "CTF v6 MySQL edition"
# Create a repo on github.com, then:
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO.git
git push -u origin main
```

---

## 💻 Run Locally

```bash
# 1. Install deps
npm install

# 2. Copy env file and fill in your MySQL credentials
cp .env.example .env
# Edit .env with your values

# 3. If you need MySQL locally, easiest with Docker:
docker run -d --name ctf-mysql \
  -e MYSQL_ROOT_PASSWORD=password \
  -e MYSQL_DATABASE=ctf \
  -p 3306:3306 mysql:8

# Then in .env set:
# MYSQL_HOST=localhost
# MYSQL_USER=root
# MYSQL_PASSWORD=password
# MYSQL_DATABASE=ctf
# MYSQL_SSL=false

# 4. Start server
npm start
# → http://localhost:3000
# → http://localhost:3000/admin  (password: danik2026)
```

---

## 🔐 Environment Variables Reference

| Variable | Description | Default |
|---|---|---|
| `MYSQL_HOST` | Database host | `localhost` |
| `MYSQL_PORT` | Database port | `3306` |
| `MYSQL_USER` | Database user | `root` |
| `MYSQL_PASSWORD` | Database password | *(empty)* |
| `MYSQL_DATABASE` | Database name | `ctf` |
| `MYSQL_SSL` | Enable SSL (`true`/`false`) | *(off)* |
| `ADMIN_PASSWORD` | Admin panel password | `danik2026` |
| `PORT` | Server port | `3000` |

---

## ⚠️ Important Notes

- **WebSockets**: Railway, Render, and Fly.io all support WebSockets natively. Vercel does NOT (serverless = no persistent connections). Use Railway or Render instead.
- Tables are created automatically on first startup — no manual SQL needed.
- Change `ADMIN_PASSWORD` before going public!
- `rank` is a reserved word in MySQL — the query uses backticks around it (already handled in the code).
