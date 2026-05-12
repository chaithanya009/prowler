import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { AccountsSelector } from "./accounts-selector";

const multiSelectContentSpy = vi.fn();
const navigateWithParamsMock = vi.fn();
let multiSelectOnValuesChange: ((values: string[]) => void) | undefined;

vi.mock("next/navigation", () => ({
  useSearchParams: () => new URLSearchParams(),
}));

vi.mock("@/hooks/use-url-filters", () => ({
  useUrlFilters: () => ({
    navigateWithParams: navigateWithParamsMock,
  }),
}));

vi.mock("@/components/icons/providers-badge", () => ({
  AWSProviderBadge: () => <span>AWS</span>,
  AzureProviderBadge: () => <span>Azure</span>,
  GCPProviderBadge: () => <span>GCP</span>,
  CloudflareProviderBadge: () => <span>Cloudflare</span>,
  GitHubProviderBadge: () => <span>GitHub</span>,
  GoogleWorkspaceProviderBadge: () => <span>Google Workspace</span>,
  IacProviderBadge: () => <span>IaC</span>,
  ImageProviderBadge: () => <span>Image</span>,
  KS8ProviderBadge: () => <span>Kubernetes</span>,
  M365ProviderBadge: () => <span>M365</span>,
  MongoDBAtlasProviderBadge: () => <span>MongoDB Atlas</span>,
  OpenStackProviderBadge: () => <span>OpenStack</span>,
  OracleCloudProviderBadge: () => <span>Oracle Cloud</span>,
  AlibabaCloudProviderBadge: () => <span>Alibaba Cloud</span>,
  VercelProviderBadge: () => <span>Vercel</span>,
  OktaProviderBadge: () => <span>Okta</span>,
}));

vi.mock("@/components/shadcn/select/multiselect", () => ({
  MultiSelect: ({
    children,
    onValuesChange,
  }: {
    children: React.ReactNode;
    onValuesChange?: (values: string[]) => void;
  }) => {
    multiSelectOnValuesChange = onValuesChange;
    return <div>{children}</div>;
  },
  MultiSelectTrigger: ({ children }: { children: React.ReactNode }) => (
    <div>{children}</div>
  ),
  MultiSelectValue: ({ placeholder }: { placeholder: string }) => (
    <span>{placeholder}</span>
  ),
  MultiSelectContent: ({
    children,
    search,
  }: {
    children: React.ReactNode;
    search?: unknown;
  }) => {
    multiSelectContentSpy(search);
    return <div>{children}</div>;
  },
  MultiSelectItem: ({
    children,
    value,
    keywords,
  }: {
    children: React.ReactNode;
    value: string;
    keywords?: string[];
  }) => (
    <div
      data-value={value}
      data-keywords={keywords?.join("|")}
      onClick={() => multiSelectOnValuesChange?.([value])}
    >
      {children}
    </div>
  ),
  MultiSelectSelectAll: ({ children }: { children: React.ReactNode }) => (
    <button type="button" onClick={() => multiSelectOnValuesChange?.([])}>
      {children}
    </button>
  ),
}));

const providers = [
  {
    id: "provider-1",
    type: "providers" as const,
    attributes: {
      provider: "aws" as const,
      uid: "123456789012",
      alias: "Production AWS",
      status: "completed" as const,
      resources: 0,
      connection: {
        connected: true,
        last_checked_at: "2026-04-13T00:00:00Z",
      },
      scanner_args: {
        only_logs: false,
        excluded_checks: [],
        aws_retries_max_attempts: 3,
      },
      inserted_at: "2026-04-13T00:00:00Z",
      updated_at: "2026-04-13T00:00:00Z",
      created_by: {
        object: "user",
        id: "user-1",
      },
    },
    relationships: {
      secret: {
        data: null,
      },
      provider_groups: {
        meta: {
          count: 0,
        },
        data: [],
      },
    },
  },
];

describe("AccountsSelector", () => {
  it("passes searchable dropdown defaults to MultiSelectContent", () => {
    render(<AccountsSelector providers={providers} />);

    expect(multiSelectContentSpy).toHaveBeenCalledWith({
      placeholder: "Search accounts...",
      emptyMessage: "No accounts found.",
    });
    expect(screen.getByText("Production AWS")).toBeInTheDocument();
  });

  it("allows disabling search explicitly", () => {
    render(<AccountsSelector providers={providers} search={false} />);

    expect(multiSelectContentSpy).toHaveBeenLastCalledWith(false);
  });

  it("passes visible account labels as search keywords instead of only the internal id", () => {
    render(<AccountsSelector providers={providers} />);

    expect(
      screen.getByText("Production AWS").closest("[data-value]"),
    ).toHaveAttribute(
      "data-keywords",
      expect.stringContaining("Production AWS"),
    );
    expect(
      screen.getByText("Production AWS").closest("[data-value]"),
    ).toHaveAttribute("data-keywords", expect.stringContaining("123456789012"));
  });

  it("clears selected accounts when All accounts is selected", async () => {
    const user = userEvent.setup();
    const onBatchChange = vi.fn();

    render(
      <AccountsSelector
        providers={providers}
        onBatchChange={onBatchChange}
        selectedValues={["provider-1"]}
      />,
    );

    await user.click(screen.getByRole("button", { name: "All accounts" }));

    expect(onBatchChange).toHaveBeenCalledWith("provider_id__in", []);
  });

  it("applies account changes immediately outside batch mode", async () => {
    const user = userEvent.setup();

    render(<AccountsSelector providers={providers} />);

    await user.click(screen.getByText("Production AWS"));

    const params = new URLSearchParams();
    navigateWithParamsMock.mock.calls[0][0](params);

    expect(params.get("filter[provider_id__in]")).toBe("provider-1");
  });
});
