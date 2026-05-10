import { Control } from "react-hook-form";

import { WizardInputField } from "@/components/providers/workflow/forms/fields";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import { OktaCredentials } from "@/types";

export const OktaCredentialsForm = ({
  control,
}: {
  control: Control<OktaCredentials>;
}) => {
  return (
    <>
      <div className="flex flex-col">
        <div className="text-md text-default-foreground leading-9 font-bold">
          Connect via API Token
        </div>
        <div className="text-default-500 text-sm">
          Provide an Okta API token with access to read System Log events.
        </div>
      </div>
      <WizardInputField
        control={control}
        name={ProviderCredentialFields.OKTA_ORG_URL}
        type="url"
        label="Org URL"
        labelPlacement="inside"
        placeholder="https://your-org.okta.com"
        variant="bordered"
        isRequired
      />
      <WizardInputField
        control={control}
        name={ProviderCredentialFields.OKTA_API_TOKEN}
        type="password"
        label="API Token"
        labelPlacement="inside"
        placeholder="Enter your Okta API token"
        variant="bordered"
        isRequired
      />
      <div className="text-default-400 text-xs">
        API tokens are stored as encrypted provider secrets.
      </div>
    </>
  );
};
