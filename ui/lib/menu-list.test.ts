import { describe, expect, it } from "vitest";

import { getMenuList } from "./menu-list";

describe("getMenuList", () => {
  it("does not include upstream Prowler support or hub links", () => {
    const menuLabels = getMenuList({ pathname: "/" }).flatMap((group) =>
      group.menus.flatMap((menu) => [
        menu.label,
        ...(menu.submenus?.map((submenu) => submenu.label) ?? []),
      ]),
    );

    expect(menuLabels).not.toContain("Support & Help");
    expect(menuLabels).not.toContain("Documentation");
    expect(menuLabels).not.toContain("API reference");
    expect(menuLabels).not.toContain("Customer Support");
    expect(menuLabels).not.toContain("Community Support");
    expect(menuLabels).not.toContain("Prowler Hub");
    expect(menuLabels).not.toContain("Compliance");
    expect(menuLabels).not.toContain("Attack Paths");
  });
});
