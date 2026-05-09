"use client";

import { ProwlerShort } from "@/components/icons";

export const ThreatScoreLogo = () => {
  return (
    <div className="flex h-14 items-center gap-3">
      <ProwlerShort width={44} height={44} />
      <span className="text-prowler-black dark:text-prowler-white text-2xl font-bold tracking-normal">
        Secto
      </span>
      <span className="text-2xl font-bold tracking-normal text-green-500">
        THREATSCORE
      </span>
    </div>
  );
};
