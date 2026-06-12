import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Emit a self-contained server bundle at .next/standalone so the production
  // image (frontend/Dockerfile) ships only the traced runtime files instead of
  // the full node_modules.
  output: "standalone",
};

export default nextConfig;
