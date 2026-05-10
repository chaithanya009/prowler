"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";

import { scanOnDemand, scheduleDaily } from "@/actions/scans";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/shadcn/select/select";
import { Spinner } from "@/components/shadcn/spinner/spinner";
import { TreeStatusIcon } from "@/components/shadcn/tree-view/tree-status-icon";
import { ToastAction, useToast } from "@/components/ui";
import { useProviderWizardStore } from "@/store/provider-wizard/store";
import { TREE_ITEM_STATUS } from "@/types/tree";

import {
  WIZARD_FOOTER_ACTION_TYPE,
  WizardFooterConfig,
} from "./footer-controls";

const SCAN_SCHEDULE = {
  DAILY: "daily",
  SINGLE: "single",
} as const;

type ScanScheduleOption = (typeof SCAN_SCHEDULE)[keyof typeof SCAN_SCHEDULE];

interface LaunchStepProps {
  onBack: () => void;
  onClose: () => void;
  onFooterChange: (config: WizardFooterConfig) => void;
}

export function LaunchStep({
  onBack,
  onClose,
  onFooterChange,
}: LaunchStepProps) {
  const { toast } = useToast();
  const { providerId, providerType } = useProviderWizardStore();
  const [isLaunching, setIsLaunching] = useState(false);
  const [scheduleOption, setScheduleOption] = useState<ScanScheduleOption>(
    SCAN_SCHEDULE.DAILY,
  );
  const launchActionRef = useRef<() => void>(() => {});

  const handleLaunchScan = async () => {
    if (!providerId) {
      return;
    }

    setIsLaunching(true);
    const formData = new FormData();
    formData.set("providerId", providerId);
    const result =
      scheduleOption === SCAN_SCHEDULE.DAILY
        ? await scheduleDaily(formData)
        : await scanOnDemand(formData);

    if (result?.error) {
      setIsLaunching(false);
      toast({
        variant: "destructive",
        title: "Unable to launch scan",
        description: String(result.error),
      });
      return;
    }

    setIsLaunching(false);
    onClose();
    if (providerType === "okta") {
      toast({
        title: "Ingestion Launched",
        description: "Okta log ingestion will run every 5 minutes.",
        action: (
          <ToastAction altText="Go to providers" asChild>
            <Link href="/providers">Go to providers</Link>
          </ToastAction>
        ),
      });
      return;
    }

    toast({
      title: "Scan Launched",
      description:
        scheduleOption === SCAN_SCHEDULE.DAILY
          ? "Daily scan scheduled successfully."
          : "Single scan launched successfully.",
      action: (
        <ToastAction altText="Go to scans" asChild>
          <Link href="/scans">Go to scans</Link>
        </ToastAction>
      ),
    });
  };

  launchActionRef.current = () => {
    void handleLaunchScan();
  };

  useEffect(() => {
    onFooterChange({
      showBack: true,
      backLabel: "Back",
      backDisabled: isLaunching,
      onBack,
      showAction: true,
      actionLabel:
        providerType === "okta"
          ? isLaunching
            ? "Launching ingestion..."
            : "Launch ingestion"
          : isLaunching
            ? "Launching scans..."
            : "Launch scan",
      actionDisabled: isLaunching || !providerId,
      actionType: WIZARD_FOOTER_ACTION_TYPE.BUTTON,
      onAction: () => {
        launchActionRef.current();
      },
    });
  }, [isLaunching, onBack, onFooterChange, providerId, providerType]);

  if (isLaunching) {
    return (
      <div className="flex min-h-[320px] items-center justify-center">
        <div className="flex items-center gap-3 py-2">
          <Spinner className="size-6" />
          <p className="text-sm font-medium">
            {providerType === "okta"
              ? "Launching ingestion..."
              : "Launching scans..."}
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-6">
      <div className="flex items-center gap-3">
        <TreeStatusIcon status={TREE_ITEM_STATUS.SUCCESS} className="size-6" />
        <h3 className="text-sm font-semibold">Connection validated!</h3>
      </div>

      <p className="text-text-neutral-secondary text-sm">
        {providerType === "okta"
          ? "Launch recurring log ingestion for this provider."
          : "Choose how you want to launch scans for this provider."}
      </p>

      {!providerId && (
        <p className="text-text-error-primary text-sm">
          Provider data is missing. Go back and test the connection again.
        </p>
      )}

      {providerType === "okta" ? (
        <p className="text-text-neutral-secondary text-sm">
          Okta System Log ingestion will run every 5 minutes.
        </p>
      ) : (
        <div className="flex flex-col gap-4">
          <p className="text-text-neutral-secondary text-sm">Scan schedule</p>
          <Select
            value={scheduleOption}
            onValueChange={(value) =>
              setScheduleOption(value as ScanScheduleOption)
            }
            disabled={isLaunching || !providerId}
          >
            <SelectTrigger className="w-full max-w-[376px]">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={SCAN_SCHEDULE.DAILY}>
                Scan Daily (every 24 hours)
              </SelectItem>
              <SelectItem value={SCAN_SCHEDULE.SINGLE}>
                Run a single scan (no recurring schedule)
              </SelectItem>
            </SelectContent>
          </Select>
        </div>
      )}
    </div>
  );
}
