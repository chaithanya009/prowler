import { ReactNode } from "react";

import { NavbarClient } from "./navbar-client";

interface NavbarProps {
  title: string;
  icon?: string | ReactNode;
}

export function Navbar({ title, icon }: NavbarProps) {
  return <NavbarClient title={title} icon={icon} />;
}
