const apiBase = process.env.NEXT_PUBLIC_INACTU_API_BASE_URL ?? "http://localhost:8080";

const principles = [
  {
    title: "Immutability",
    body: "Skills are content-addressed and signed. If bytes change, identity changes."
  },
  {
    title: "Explicit Capabilities",
    body: "No ambient authority. Every file, network, and execution boundary is declared."
  },
  {
    title: "Verifiable Provenance",
    body: "Every run can be traced from source to receipt with cryptographic integrity."
  }
];

const routes = [
  "GET /healthz",
  "POST /v1/hash/sha256",
  "POST /v1/verify/manifest",
  "POST /v1/verify/receipt"
];

export default function Home() {
  return (
    <main className="page">
      <section className="hero">
        <p className="chip">Inactu Control Plane</p>
        <h1>Verifiable execution infrastructure for skills that must be trusted.</h1>
        <p className="lede">
          Inactu executes immutable artifacts with strict capabilities, policy checks, and auditable receipts.
          The control plane gives teams a service surface around that substrate.
        </p>
        <div className="cta-row">
          <a className="btn btn-primary" href="/docs">
            Explore Docs
          </a>
          <a className="btn btn-secondary" href={apiBase} target="_blank" rel="noreferrer">
            API Base
          </a>
        </div>
      </section>

      <section className="grid two-up">
        <article className="card">
          <h2>Core Principles</h2>
          <ul>
            {principles.map((item) => (
              <li key={item.title}>
                <h3>{item.title}</h3>
                <p>{item.body}</p>
              </li>
            ))}
          </ul>
        </article>

        <article className="card">
          <h2>Control Plane API</h2>
          <p>Current backend routes exposed by the Rust service:</p>
          <ul className="mono-list">
            {routes.map((route) => (
              <li key={route}>{route}</li>
            ))}
          </ul>
          <p className="small">Set <code>NEXT_PUBLIC_INACTU_API_BASE_URL</code> for deployed environments.</p>
        </article>
      </section>
    </main>
  );
}
