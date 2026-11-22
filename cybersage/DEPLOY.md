# Deploying CyberSage

Pick one. Both give a link anyone can open. Test the link in an incognito window before putting it in the form.

## Option A: static page (fastest, no server, no key)

`web/index.html` is one self-contained file. It runs the offline engine in the browser and includes the live test table.

- **Netlify Drop:** go to https://app.netlify.com/drop and drag the `web` folder in. You get a public URL immediately.
- **GitHub Pages:** push the repo, then Settings > Pages > deploy from branch, folder `/web`.
- **Vercel:** import the repo and set the root directory to `web`.

If you change `web/engine.js`, `web/index.template.html` or the test cases, rebuild with `python web/build.py`.

## Option B: full Python app on Render (can use the real LLM)

1. Push this project to GitHub (without any `.env` file).
2. On https://render.com choose New > Blueprint (or Web Service), pick the repo. `render.yaml` sets everything up.
3. In the service's Environment tab add `OPENAI_API_KEY`. Never put the key in the repo.
4. Open the `onrender.com` URL. `/api/health` shows whether the LLM is configured.

Free instances sleep when idle, so open the link once before the evaluators do. Docker works too: `docker build -t cybersage . && docker run -p 8000:8000 -e OPENAI_API_KEY=... cybersage`.

## Prototype link for the form (Q11)

Use the Render URL if you want evaluators to try the LLM version, otherwise the static URL. If you share a claude.ai artifact link instead, open the artifact's Share menu and set access so anyone with the link can view; a private artifact asks evaluators for access and scores 0.
