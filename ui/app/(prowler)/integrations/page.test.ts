import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("integrations page", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const source = readFileSync(path.join(currentDir, "page.tsx"), "utf8");

  it("does not render the API keys integration card", () => {
    expect(source).not.toContain("ApiKeyLinkCard");
    expect(source).not.toContain("API Keys");
  });
});
