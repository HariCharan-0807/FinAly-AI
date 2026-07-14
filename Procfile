# FinAly AI — Backend Deployment Guide for Vercel Hosting
# =========================================================
# Your frontend (HTML/CSS/JS) deploys to Vercel.
# Your Python FastAPI backend deploys to Railway or Render.
#
# Steps:
# 1. Push your project to a GitHub repo.
# 2. Deploy frontend to Vercel (import from GitHub).
# 3. Deploy backend to Railway:
#    - Connect GitHub repo
#    - Set all .env variables in Railway's environment settings
#    - Railway auto-detects Python and runs uvicorn
# 4. Update the API URL in index.html <meta name="api-url"> tag.

# ── Railway Procfile (rename to Procfile, no extension) ───
web: python main.py
