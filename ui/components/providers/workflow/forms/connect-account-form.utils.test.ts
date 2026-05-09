import { describe, expect, it } from "vitest";

import {
  getAddProviderErrorMessage,
  getCreatedProvider,
} from "./connect-account-form.utils";

describe("connect account form response helpers", () => {
  it("returns the created provider when the add provider response has data", () => {
    const provider = {
      id: "provider-1",
      type: "providers",
      attributes: {
        provider: "m365",
        uid: "example.onmicrosoft.com",
        alias: "Example",
      },
    };

    expect(getCreatedProvider({ data: provider })).toBe(provider);
    expect(getAddProviderErrorMessage({ data: provider })).toBeNull();
  });

  it("uses the server error instead of treating a missing data payload as success", () => {
    expect(
      getAddProviderErrorMessage({
        error: "Provider already exists.",
        status: 409,
      }),
    ).toBe("Provider already exists.");
  });

  it("returns a fallback error when the response has no created provider", () => {
    expect(getCreatedProvider({ success: true, status: 204 })).toBeNull();
    expect(getAddProviderErrorMessage({ success: true, status: 204 })).toBe(
      "The provider could not be created. Please try again.",
    );
  });
});
