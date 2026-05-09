"use client";

import { useSearchParams } from "next/navigation";
import { type ComponentType, lazy, Suspense } from "react";

import {
  MultiSelect,
  MultiSelectContent,
  MultiSelectItem,
  type MultiSelectSearchProp,
  MultiSelectTrigger,
  MultiSelectValue,
} from "@/components/shadcn/select/multiselect";
import { useUrlFilters } from "@/hooks/use-url-filters";
import { type ProviderProps, ProviderType } from "@/types/providers";

const M365ProviderBadge = lazy(() =>
  import("@/components/icons/providers-badge").then((m) => ({
    default: m.M365ProviderBadge,
  })),
);

type IconProps = { width: number; height: number };

const IconPlaceholder = ({ width, height }: IconProps) => (
  <div style={{ width, height }} />
);

const PROVIDER_DATA: Record<
  Extract<ProviderType, "m365">,
  { label: string; icon: ComponentType<IconProps> }
> = {
  m365: {
    label: "Microsoft 365",
    icon: M365ProviderBadge,
  },
};

type VisibleProviderType = keyof typeof PROVIDER_DATA;

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
  ).filter((type): type is VisibleProviderType => type === "m365");

  const handleMultiValueChange = (values: string[]) => {
    if (onBatchChange) {
      onBatchChange("provider_type__in", values);
      return;
    }
    navigateWithParams((params) => {
      // Update provider_type__in
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
    .filter((type): type is VisibleProviderType => type === "m365")
    .sort((a, b) =>
      PROVIDER_DATA[a].label.localeCompare(PROVIDER_DATA[b].label),
    );

  const renderIcon = (providerType: VisibleProviderType) => {
    const IconComponent = PROVIDER_DATA[providerType].icon;
    return (
      <Suspense fallback={<IconPlaceholder width={24} height={24} />}>
        <IconComponent width={24} height={24} />
      </Suspense>
    );
  };

  const selectedLabel = () => {
    if (selectedTypes.length === 0) return null;
    if (selectedTypes.length === 1) {
      const providerType = selectedTypes[0];
      return (
        <span className="flex min-w-0 items-center gap-2">
          {renderIcon(providerType)}
          <span className="truncate">{PROVIDER_DATA[providerType].label}</span>
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
              <div
                role="option"
                aria-selected={selectedTypes.length === 0}
                aria-label="Select all providers (clears current selection to show all)"
                tabIndex={0}
                className="text-text-neutral-secondary flex w-full cursor-pointer items-center gap-3 rounded-lg px-4 py-3 text-sm font-semibold hover:bg-slate-200 dark:hover:bg-slate-700/50"
                onClick={() => handleMultiValueChange([])}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    handleMultiValueChange([]);
                  }
                }}
              >
                Select All
              </div>
              {availableTypes.map((providerType) => (
                <MultiSelectItem
                  key={providerType}
                  value={providerType}
                  badgeLabel={PROVIDER_DATA[providerType].label}
                  keywords={[providerType, PROVIDER_DATA[providerType].label]}
                  aria-label={`${PROVIDER_DATA[providerType].label} provider`}
                >
                  <span aria-hidden="true">{renderIcon(providerType)}</span>
                  <span>{PROVIDER_DATA[providerType].label}</span>
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
