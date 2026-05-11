import { describe, expect, it, vi } from "vitest";

import { ProviderCredentialFields } from "./provider-credential-fields";

vi.mock("@/lib", () => ({
  filterEmptyValues: (value: Record<string, unknown>) =>
    Object.fromEntries(
      Object.entries(value).filter(
        ([, item]) => item !== undefined && item !== null && item !== "",
      ),
    ),
  getFormValue: (formData: FormData, key: string) => formData.get(key),
}));

describe("buildSecretConfig", () => {
  it("builds Okta API token credentials", async () => {
    const { buildSecretConfig } = await import("./build-crendentials");
    const formData = new FormData();
    formData.set(ProviderCredentialFields.OKTA_API_TOKEN, " fake-api-token ");

    expect(buildSecretConfig(formData, "okta")).toEqual({
      secretType: "static",
      secret: {
        api_token: "fake-api-token",
      },
    });
  });
});
