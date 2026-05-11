"use client";

import { ChevronDown } from "lucide-react";
import { useState } from "react";

import { AccountsSelector } from "@/app/(prowler)/_overview/_components/accounts-selector";
import { ProviderTypeSelector } from "@/app/(prowler)/_overview/_components/provider-type-selector";
import { Button } from "@/components/shadcn";
import { ExpandableSection } from "@/components/ui/expandable-section";
import { DataTableFilterCustom } from "@/components/ui/table";
import { getGroupLabel } from "@/lib/categories";
import { ProviderProps } from "@/types/providers";

import { getResourcesFilterDisplayValue } from "./resources-filters.utils";

interface ResourcesFiltersProps {
  providers: ProviderProps[];
  uniqueRegions: string[];
  uniqueServices: string[];
  uniqueResourceTypes: string[];
  uniqueGroups: string[];
}

export const ResourcesFilters = ({
  providers,
  uniqueRegions,
  uniqueServices,
  uniqueResourceTypes,
  uniqueGroups,
}: ResourcesFiltersProps) => {
  const [isExpanded, setIsExpanded] = useState(false);

  const customFilters = [
    {
      key: "region__in",
      labelCheckboxGroup: "Regions",
      values: uniqueRegions,
      index: 1,
    },
    {
      key: "service__in",
      labelCheckboxGroup: "Services",
      values: uniqueServices,
      index: 2,
    },
    {
      key: "type__in",
      labelCheckboxGroup: "Types",
      values: uniqueResourceTypes,
      index: 3,
    },
    {
      key: "groups__in",
      labelCheckboxGroup: "Groups",
      values: uniqueGroups,
      labelFormatter: getGroupLabel,
      index: 4,
    },
  ];

  const hasCustomFilters = customFilters.length > 0;

  const expandedFilters = hasCustomFilters ? (
    <ExpandableSection isExpanded={isExpanded} contentClassName="pt-0">
      <DataTableFilterCustom
        gridClassName="gap-3"
        filters={customFilters.map((filter) => ({
          ...filter,
          labelFormatter: (value: string) =>
            getResourcesFilterDisplayValue(
              `filter[${filter.key}]`,
              value,
              providers,
            ),
        }))}
      />
    </ExpandableSection>
  ) : null;

  return (
    <div className="flex flex-col gap-3">
      <div
        data-testid="resources-filter-controls"
        className="flex flex-wrap items-center gap-4"
      >
        <div className="min-w-[200px] flex-1 md:max-w-[280px]">
          <ProviderTypeSelector providers={providers} />
        </div>
        <div className="min-w-[200px] flex-1 md:max-w-[280px]">
          <AccountsSelector providers={providers} />
        </div>
        {hasCustomFilters && (
          <Button
            variant="outline"
            size="lg"
            onClick={() => setIsExpanded(!isExpanded)}
          >
            {isExpanded ? "Less Filters" : "More Filters"}
            <ChevronDown
              className={`size-4 transition-transform duration-300 ${isExpanded ? "rotate-180" : "rotate-0"}`}
            />
          </Button>
        )}
      </div>
      {expandedFilters ? (
        <div
          data-testid="resources-expanded-filters"
          className={isExpanded ? undefined : "hidden"}
        >
          {expandedFilters}
        </div>
      ) : null}
    </div>
  );
};
