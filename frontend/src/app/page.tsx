import Link from "next/link";

export default function Home() {
  const cards: { href: string; title: string; desc: string }[] = [
    {
      href: "/dashboard",
      title: "Executive Dashboard",
      desc: "Org-wide risk posture, asset heatmap, and real-time runtime telemetry.",
    },
    {
      href: "/assets",
      title: "Assets",
      desc: "Register AI assets you want to protect — models, agents, RAG systems, copilots.",
    },
    {
      href: "/evaluations",
      title: "Evaluations",
      desc: "Run the test case library against your assets. See pass/fail, score, findings.",
    },
    {
      href: "/findings",
      title: "Findings",
      desc: "Track vulnerabilities through open → remediated. Filter by severity / asset.",
    },
    {
      href: "/redteam",
      title: "Red Team",
      desc: "Generative adversarial campaigns. Auto-promoted regression cases on success.",
    },
    {
      href: "/anomalies",
      title: "Anomalies",
      desc: "Real-time anomalies detected on the attack graph: volume spikes, novel transitions, risk inflation.",
    },
    {
      href: "/threat-intel",
      title: "Threat Intel",
      desc: "Cross-tenant attack pattern clusters and novel-technique detections. Export as STIX 2.1.",
    },
    {
      href: "/connectors",
      title: "Connectors",
      desc: "Register OpenAI / Anthropic / Ollama / Azure / Bedrock / custom endpoints.",
    },
    {
      href: "/compliance",
      title: "Compliance",
      desc: "Download SOC 2 / ISO 27001 / FedRAMP evidence packs over a period.",
    },
  ];

  return (
    <div>
      <header className="mb-8">
        <h1 className="text-2xl font-semibold text-slate-900">
          AI Security Platform
        </h1>
        <p className="mt-1 text-sm text-slate-600">
          Evaluate, monitor, and protect your AI assets.
        </p>
      </header>
      <ul className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {cards.map((c) => (
          <li key={c.href}>
            <Link
              href={c.href}
              className="block rounded-lg border border-slate-200 bg-white p-5 transition hover:border-slate-300 hover:shadow-sm"
            >
              <h2 className="text-lg font-medium text-slate-900">{c.title}</h2>
              <p className="mt-1 text-sm text-slate-600">{c.desc}</p>
            </Link>
          </li>
        ))}
      </ul>
    </div>
  );
}
