# inactu-web

Next.js frontend scaffold for the Inactu control plane.

## Local development

```bash
cd apps/inactu-control/web
npm install
npm run dev
```

Set the backend API base URL in `.env.local`:

```bash
NEXT_PUBLIC_INACTU_API_BASE_URL=http://localhost:8080
```

## Deploy on Vercel

- Import this directory as the Vercel project root: `apps/inactu-control/web`
- Framework preset: Next.js
- Build command: `npm run build`
- Output directory: `.next`
- Environment variable: `NEXT_PUBLIC_INACTU_API_BASE_URL=<your-api-url>`

The Rust control-plane API should run separately (for example on Fly.io, Render, Railway, or ECS), and the Next.js app calls it.
