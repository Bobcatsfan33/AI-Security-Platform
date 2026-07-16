/**
 * Preview badge — the UI half of the Tier B designation.
 *
 * The backend stamps the `preview` OpenAPI tag on every Tier B route
 * (see backend/app/core/tiers.py); this is the same claim rendered for a
 * human. Tier B is shipped and usable, but not held to the hardening bar of
 * the agent/MCP security surface — an evaluator should know which surface
 * they are standing on before they lean on it.
 *
 * TIER_B_ROUTES is asserted against the backend registry by
 * `test_frontend_preview_routes_match_backend_tier_b` in
 * backend/tests/unit/test_tiers.py, so a route that changes tier on one side
 * cannot silently keep or lose its badge on the other.
 */

/** Frontend routes whose backing API is Tier B. */
export const TIER_B_ROUTES: readonly string[] = [
  "/redteam",
  "/evaluations",
  "/findings",
  "/test-cases",
  "/reports",
  "/compliance",
];

export function isPreviewRoute(pathname: string): boolean {
  return TIER_B_ROUTES.some(
    (route) => pathname === route || pathname.startsWith(`${route}/`),
  );
}

interface PreviewBadgeProps {
  /** `inline` sits next to a nav label; `heading` sits beside a page title. */
  variant?: "inline" | "heading";
}

export function PreviewBadge({ variant = "inline" }: PreviewBadgeProps) {
  const size = variant === "heading" ? "text-xs" : "text-[10px]";
  return (
    <span
      title="Preview: shipped and usable, but thinner tests and no stability guarantee. See docs/TIERS.md."
      className={`rounded-full bg-amber-100 px-2 py-0.5 font-medium uppercase tracking-wide text-amber-800 ${size}`}
    >
      Preview
    </span>
  );
}
