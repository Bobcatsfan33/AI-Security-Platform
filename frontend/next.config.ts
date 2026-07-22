import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Emit a self-contained server bundle at .next/standalone so the production
  // image (frontend/Dockerfile) ships only the traced runtime files instead of
  // the full node_modules.
  output: "standalone",
  // next/image is unused across this dashboard (no <Image>, no next/image
  // import), so disable optimization — Next then never invokes sharp at
  // runtime. See frontend/audit-exceptions.json.
  images: { unoptimized: true },
  // Belt-and-braces: the file tracer still bundles sharp even when it is never
  // imported, so exclude it (and its @img libvips natives) explicitly. This is
  // what actually keeps the vulnerable dependency OUT of the .next/standalone
  // bundle the production image ships — verified absent from the build.
  outputFileTracingExcludes: { "*": ["node_modules/sharp/**", "node_modules/@img/**"] },
};

export default nextConfig;
