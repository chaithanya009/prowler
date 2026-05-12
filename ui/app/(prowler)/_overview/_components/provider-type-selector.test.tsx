import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { ProviderTypeSelector } from "./provider-type-selector";

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
  KS8ProviderBadge: () => <span>Kubernetes</span>,
  M365ProviderBadge: () => <span>M365</span>,
  GitHubProviderBadge: () => <span>GitHub</span>,
  GoogleWorkspaceProviderBadge: () => <span>Google Workspace</span>,
  IacProviderBadge: () => <span>IaC</span>,
  ImageProviderBadge: () => <span>Image</span>,
  OracleCloudProviderBadge: () => <span>Oracle Cloud</span>,
  MongoDBAtlasProviderBadge: () => <span>MongoDB Atlas</span>,
  AlibabaCloudProviderBadge: () => <span>Alibaba Cloud</span>,
  CloudflareProviderBadge: () => <span>Cloudflare</span>,
  OpenStackProviderBadge: () => <span>OpenStack</span>,
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
    id: "provider-0",
    type: "providers" as const,
    attributes: {
      provider: "aws" as const,
      uid: "210987654321",
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
  {
    id: "provider-1",
    type: "providers" as const,
    attributes: {
      provider: "m365" as const,
      uid: "123456789012",
      alias: "Production M365",
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
  {
    id: "provider-2",
    type: "providers" as const,
    attributes: {
      provider: "okta" as const,
      uid: "trial-9904034",
      alias: "Production Okta",
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

describe("ProviderTypeSelector", () => {
  it("passes searchable dropdown defaults to MultiSelectContent", () => {
    render(<ProviderTypeSelector providers={providers} />);

    expect(multiSelectContentSpy).toHaveBeenCalledWith({
      placeholder: "Search providers...",
      emptyMessage: "No providers found.",
    });
    expect(screen.getByText("Microsoft 365")).toBeInTheDocument();
  });

  it("allows disabling search explicitly", () => {
    render(<ProviderTypeSelector providers={providers} search={false} />);

    expect(multiSelectContentSpy).toHaveBeenLastCalledWith(false);
  });

  it("passes provider label as search keywords", () => {
    render(<ProviderTypeSelector providers={providers} />);

    expect(
      screen.getByText("Microsoft 365").closest("[data-value]"),
    ).toHaveAttribute(
      "data-keywords",
      expect.stringContaining("Microsoft 365"),
    );
  });

  it("shows every provider type available on the findings page", () => {
    render(<ProviderTypeSelector providers={providers} />);

    expect(
      screen.getAllByText("AWS")[0].closest("[data-value]"),
    ).toHaveAttribute("data-value", "aws");
    expect(screen.getByText("Microsoft 365")).toBeInTheDocument();
  });

  it("clears selected provider types when All providers is selected", async () => {
    const user = userEvent.setup();
    const onBatchChange = vi.fn();

    render(
      <ProviderTypeSelector
        providers={providers}
        onBatchChange={onBatchChange}
        selectedValues={["aws"]}
      />,
    );

    await user.click(screen.getByRole("button", { name: "All providers" }));

    expect(onBatchChange).toHaveBeenCalledWith("provider_type__in", []);
  });

  it("applies provider type changes immediately outside batch mode", async () => {
    const user = userEvent.setup();

    render(<ProviderTypeSelector providers={providers} />);

    await user.click(screen.getAllByText("Okta")[0].closest("[data-value]")!);

    const params = new URLSearchParams({
      "filter[provider_id__in]": "provider-1",
    });
    navigateWithParamsMock.mock.calls[0][0](params);

    expect(params.get("filter[provider_type__in]")).toBe("okta");
    expect(params.get("filter[provider_id__in]")).toBeNull();
  });
});
