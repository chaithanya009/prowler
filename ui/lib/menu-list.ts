import {
  CloudCog,
  Mail,
  Puzzle,
  Settings,
  SquareChartGantt,
  Tag,
  Timer,
  User,
  UserCog,
  Users,
  VolumeX,
  Warehouse,
} from "lucide-react";

import { GroupProps } from "@/types";

interface MenuListOptions {
  pathname: string;
}

export const getMenuList = ({ pathname }: MenuListOptions): GroupProps[] => {
  return [
    {
      groupLabel: "",
      menus: [
        {
          href: "/",
          label: "Overview",
          icon: SquareChartGantt,
          active: pathname === "/",
        },
      ],
    },
    {
      groupLabel: "",
      menus: [
        {
          href: "/findings?filter[muted]=false&filter[status__in]=FAIL",
          label: "Findings",
          icon: Tag,
        },
      ],
    },
    {
      groupLabel: "",
      menus: [
        {
          href: "/resources",
          label: "Resources",
          icon: Warehouse,
        },
      ],
    },
    {
      groupLabel: "",
      menus: [
        {
          href: "",
          label: "Configuration",
          icon: Settings,
          submenus: [
            { href: "/providers", label: "Providers", icon: CloudCog },
            {
              href: "/mutelist",
              label: "Mutelist",
              icon: VolumeX,
              active: pathname === "/mutelist",
            },
            { href: "/scans", label: "Scan Jobs", icon: Timer },
            { href: "/integrations", label: "Integrations", icon: Puzzle },
            { href: "/roles", label: "Roles", icon: UserCog },
          ],
          defaultOpen: true,
        },
      ],
    },
    {
      groupLabel: "",
      menus: [
        {
          href: "",
          label: "Organization",
          icon: Users,
          submenus: [
            { href: "/users", label: "Users", icon: User },
            { href: "/invitations", label: "Invitations", icon: Mail },
          ],
          defaultOpen: false,
        },
      ],
    },
  ];
};
