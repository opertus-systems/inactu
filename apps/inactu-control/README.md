# inactu-control (experimental scaffold)

This directory is an experimental SaaS/control-plane scaffold inside the
`inactu` repository.

It exists so application work can start immediately and then be moved into its own repository.

## Scope

- API surface for control-plane concerns.
- Reuse of `inactu-verifier` for validation-heavy endpoints.
- No changes to Inactu runtime trust boundaries.
- Includes a Next.js frontend scaffold at `apps/inactu-control/web`.

## Run

```bash
cargo run -p inactu-control
```

Optional environment variables:

- `INACTU_CONTROL_BIND` (default: `127.0.0.1:8080`)
- `RUST_LOG` (default: `info`)

## Frontend (Next.js)

```bash
cd apps/inactu-control/web
npm install
npm run dev
```

Set `NEXT_PUBLIC_INACTU_API_BASE_URL` in `apps/inactu-control/web/.env.local`.

Vercel deployment: use `apps/inactu-control/web` as the project root.

## Run with Docker

Build and run with Docker Compose:

```bash
docker compose -f apps/inactu-control/compose.yaml up --build
```

The service is exposed on `http://localhost:8080`.

## Endpoints

- `GET /healthz`
- `POST /v1/verify/manifest`
- `POST /v1/verify/receipt`
- `POST /v1/hash/sha256`

## OpenAPI

- OpenAPI document: `apps/inactu-control/openapi.yaml`
- Request examples:
  - `apps/inactu-control/examples/hash-request.json`
  - `apps/inactu-control/examples/verify-manifest-request.json`
  - `apps/inactu-control/examples/verify-receipt-request.json`

Quick curl examples:

```bash
curl -s http://localhost:8080/healthz

curl -s -X POST http://localhost:8080/v1/hash/sha256 \
  -H 'content-type: application/json' \
  --data @apps/inactu-control/examples/hash-request.json

curl -s -X POST http://localhost:8080/v1/verify/manifest \
  -H 'content-type: application/json' \
  --data @apps/inactu-control/examples/verify-manifest-request.json

curl -s -X POST http://localhost:8080/v1/verify/receipt \
  -H 'content-type: application/json' \
  --data @apps/inactu-control/examples/verify-receipt-request.json
```

## Move-Out Plan

1. Create a new repository (`inactu-control`).
2. Copy `apps/inactu-control/*` to the new repository.
3. Replace the path dependency on `inactu-verifier` with a git or published crate dependency.
4. Remove `apps/inactu-control` from this workspace.
