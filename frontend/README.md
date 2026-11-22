# ThreatSense AI dashboard

React 18 single-page dashboard built with Vite. It submits artifacts to the ThreatSense AI FastAPI backend and displays the returned risk report.

## Run locally

Requires Node.js 18 or newer. Start the backend first; by default it listens on `http://127.0.0.1:8000`.

```bash
npm install
npm run dev
```

Open <http://localhost:5173>. The dashboard uses `http://127.0.0.1:8000` unless `VITE_API_URL` is set. To use a different API, copy `.env.example` to `.env.local` and edit `VITE_API_URL`.

## Other commands

```bash
npm run build    # Create the production build in dist/
npm run preview  # Preview the production build locally
npm run lint     # Run ESLint
```

For backend setup, API endpoints, configuration, and Docker instructions, see the [project README](../README.md).
