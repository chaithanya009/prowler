import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("profile page", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const source = readFileSync(path.join(currentDir, "page.tsx"), "utf8");

  it("does not render API key management", () => {
    expect(source).not.toContain("ApiKeysCard");
    expect(source).not.toContain("api-keys");
  });
});
