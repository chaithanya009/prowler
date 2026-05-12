"use client";

import { useSearchParams } from "next/navigation";
import { type ReactNode } from "react";

import {
  AlibabaCloudProviderBadge,
  AWSProviderBadge,
  AzureProviderBadge,
  CloudflareProviderBadge,
  GCPProviderBadge,
  GitHubProviderBadge,
  GoogleWorkspaceProviderBadge,
  IacProviderBadge,
  ImageProviderBadge,
  KS8ProviderBadge,
  M365ProviderBadge,
  MongoDBAtlasProviderBadge,
  OktaProviderBadge,
  OpenStackProviderBadge,
  OracleCloudProviderBadge,
  VercelProviderBadge,
} from "@/components/icons/providers-badge";
import {
  MultiSelect,
  MultiSelectContent,
  MultiSelectItem,
  type MultiSelectSearchProp,
  MultiSelectSelectAll,
  MultiSelectTrigger,
  MultiSelectValue,
} from "@/components/shadcn/select/multiselect";
import { useUrlFilters } from "@/hooks/use-url-filters";
import {
  getProviderDisplayName,
  type ProviderProps,
  type ProviderType,
} from "@/types/providers";

const PROVIDER_ICON: Record<ProviderType, ReactNode> = {
  aws: <AWSProviderBadge width={24} height={24} />,
  azure: <AzureProviderBadge width={24} height={24} />,
  gcp: <GCPProviderBadge width={24} height={24} />,
  kubernetes: <KS8ProviderBadge width={24} height={24} />,
  m365: <M365ProviderBadge width={24} height={24} />,
  github: <GitHubProviderBadge width={24} height={24} />,
  googleworkspace: <GoogleWorkspaceProviderBadge width={24} height={24} />,
  iac: <IacProviderBadge width={24} height={24} />,
  image: <ImageProviderBadge width={24} height={24} />,
  oraclecloud: <OracleCloudProviderBadge width={24} height={24} />,
  mongodbatlas: <MongoDBAtlasProviderBadge width={24} height={24} />,
  alibabacloud: <AlibabaCloudProviderBadge width={24} height={24} />,
  cloudflare: <CloudflareProviderBadge width={24} height={24} />,
  openstack: <OpenStackProviderBadge width={24} height={24} />,
  vercel: <VercelProviderBadge width={24} height={24} />,
  okta: <OktaProviderBadge width={24} height={24} />,
};

/** Common props shared by both batch and instant modes. */
interface ProviderTypeSelectorBaseProps {
  providers: ProviderProps[];
  search?: MultiSelectSearchProp;
}

/** Batch mode: caller controls both pending state and notification callback (all-or-nothing). */
interface ProviderTypeSelectorBatchProps extends ProviderTypeSelectorBaseProps {
  /**
   * Called instead of navigating immediately.
   * Use this on pages that batch filter changes (e.g. Findings).
   *
   * @param filterKey - The raw filter key without "filter[]" wrapper, e.g. "provider_type__in"
   * @param values - The selected values array
   */
  onBatchChange: (filterKey: string, values: string[]) => void;
  /**
   * Pending selected values controlled by the parent.
   * Reflects pending state before Apply is clicked.
   */
  selectedValues: string[];
}

/** Instant mode: URL-driven — neither callback nor controlled value. */
interface ProviderTypeSelectorInstantProps
  extends ProviderTypeSelectorBaseProps {
  onBatchChange?: never;
  selectedValues?: never;
}

type ProviderTypeSelectorProps =
  | ProviderTypeSelectorBatchProps
  | ProviderTypeSelectorInstantProps;

export const ProviderTypeSelector = ({
  providers,
  onBatchChange,
  selectedValues,
  search = {
    placeholder: "Search providers...",
    emptyMessage: "No providers found.",
  },
}: ProviderTypeSelectorProps) => {
  const searchParams = useSearchParams();
  const { navigateWithParams } = useUrlFilters();

  const currentProviders = searchParams.get("filter[provider_type__in]") || "";
  const urlSelectedTypes = currentProviders
    ? currentProviders.split(",").filter(Boolean)
    : [];

  // In batch mode, use the parent-controlled pending values; otherwise, use URL state.
  const selectedTypes = (
    onBatchChange ? selectedValues : urlSelectedTypes
  ).filter((type): type is ProviderType => type in PROVIDER_ICON);

  const handleMultiValueChange = (values: string[]) => {
    if (onBatchChange) {
      onBatchChange("provider_type__in", values);
      return;
    }
    navigateWithParams((params) => {
      params.delete("filter[provider_id__in]");

      if (values.length > 0) {
        params.set("filter[provider_type__in]", values.join(","));
      } else {
        params.delete("filter[provider_type__in]");
      }
    });
  };

  const availableTypes = Array.from(
    new Set(
      providers
        // .filter((p) => p.attributes.connection?.connected)
        .map((p) => p.attributes.provider),
    ),
  )
    .filter((type): type is ProviderType => type in PROVIDER_ICON)
    .sort((a, b) =>
      getProviderDisplayName(a).localeCompare(getProviderDisplayName(b)),
    );

  const renderIcon = (providerType: ProviderType) =>
    PROVIDER_ICON[providerType];

  const selectedLabel = () => {
    if (selectedTypes.length === 0) return null;
    if (selectedTypes.length === 1) {
      const providerType = selectedTypes[0];
      return (
        <span className="flex min-w-0 items-center gap-2">
          {renderIcon(providerType)}
          <span className="truncate">
            {getProviderDisplayName(providerType)}
          </span>
        </span>
      );
    }
    return (
      <span className="min-w-0 truncate">
        {selectedTypes.length} providers selected
      </span>
    );
  };

  return (
    <div className="relative">
      <label
        htmlFor="provider-type-selector"
        className="sr-only"
        id="provider-type-label"
      >
        Filter by provider type. Select one or more providers to view findings.
      </label>
      <MultiSelect
        values={selectedTypes}
        onValuesChange={handleMultiValueChange}
      >
        <MultiSelectTrigger
          id="provider-type-selector"
          aria-labelledby="provider-type-label"
        >
          {selectedLabel() || <MultiSelectValue placeholder="All providers" />}
        </MultiSelectTrigger>
        <MultiSelectContent search={search}>
          {availableTypes.length > 0 ? (
            <>
              <MultiSelectSelectAll>All providers</MultiSelectSelectAll>
              {availableTypes.map((providerType) => (
                <MultiSelectItem
                  key={providerType}
                  value={providerType}
                  badgeLabel={getProviderDisplayName(providerType)}
                  keywords={[
                    providerType,
                    getProviderDisplayName(providerType),
                  ]}
                  aria-label={`${getProviderDisplayName(providerType)} provider`}
                >
                  <span aria-hidden="true">{renderIcon(providerType)}</span>
                  <span>{getProviderDisplayName(providerType)}</span>
                </MultiSelectItem>
              ))}
            </>
          ) : (
            <div className="px-3 py-2 text-sm text-slate-500 dark:text-slate-400">
              No connected providers available
            </div>
          )}
        </MultiSelectContent>
      </MultiSelect>
    </div>
  );
};
