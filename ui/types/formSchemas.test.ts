import { describe, expect, it } from "vitest";

import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";

import {
  addCredentialsFormSchema,
  addCredentialsRoleFormSchema,
  addProviderFormSchema,
} from "./formSchemas";

const BASE_AWS_ROLE_VALUES = {
  [ProviderCredentialFields.PROVIDER_ID]: "provider-123",
  [ProviderCredentialFields.PROVIDER_TYPE]: "aws",
  [ProviderCredentialFields.ROLE_ARN]:
    "arn:aws:iam::123456789012:role/ProwlerRole",
  [ProviderCredentialFields.EXTERNAL_ID]: "tenant-123",
  [ProviderCredentialFields.CREDENTIALS_TYPE]: "access-secret-key",
} as const;

describe("addCredentialsRoleFormSchema", () => {
  it("accepts AWS role credentials when access and secret keys are present", () => {
    const schema = addCredentialsRoleFormSchema("aws");

    const result = schema.safeParse({
      ...BASE_AWS_ROLE_VALUES,
      [ProviderCredentialFields.AWS_ACCESS_KEY_ID]: "AKIA1234567890EXAMPLE",
      [ProviderCredentialFields.AWS_SECRET_ACCESS_KEY]:
        "test/secret+access=key1234567890",
    });

    expect(result.success).toBe(true);
  });

  it("reports missing AWS secret access key on aws_secret_access_key field", () => {
    const schema = addCredentialsRoleFormSchema("aws");

    const result = schema.safeParse({
      ...BASE_AWS_ROLE_VALUES,
      [ProviderCredentialFields.AWS_ACCESS_KEY_ID]: "AKIA1234567890EXAMPLE",
      [ProviderCredentialFields.AWS_SECRET_ACCESS_KEY]: "",
    });

    expect(result.success).toBe(false);
    if (result.success) return;

    expect(result.error.issues).toContainEqual(
      expect.objectContaining({
        path: [ProviderCredentialFields.AWS_SECRET_ACCESS_KEY],
      }),
    );
  });
});

describe("addProviderFormSchema", () => {
  it("accepts an Okta org domain without a scheme", () => {
    const result = addProviderFormSchema.safeParse({
      providerType: "okta",
      providerAlias: "Okta",
      providerUid: "acme.okta.com",
    });

    expect(result.success).toBe(true);
  });

  it("rejects an Okta org domain with a scheme", () => {
    const result = addProviderFormSchema.safeParse({
      providerType: "okta",
      providerAlias: "Okta",
      providerUid: "https://acme.okta.com",
    });

    expect(result.success).toBe(false);
  });
});

describe("addCredentialsFormSchema", () => {
  it("requires Okta org URL and API token", () => {
    const schema = addCredentialsFormSchema("okta");

    const result = schema.safeParse({
      [ProviderCredentialFields.PROVIDER_ID]: "provider-1",
      [ProviderCredentialFields.PROVIDER_TYPE]: "okta",
      [ProviderCredentialFields.OKTA_ORG_URL]: "https://acme.okta.com",
      [ProviderCredentialFields.OKTA_API_TOKEN]: "fake-api-token",
    });

    expect(result.success).toBe(true);
  });
});
