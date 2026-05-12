import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("FindingsFilters", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const source = readFileSync(path.join(currentDir, "findings-filters.tsx"), {
    encoding: "utf8",
  });

  it("uses instant provider and account selectors on the findings page", () => {
    expect(source).toContain("<ProviderTypeSelector providers={providers} />");
    expect(source).toContain("<AccountsSelector providers={providers} />");
  });
});
