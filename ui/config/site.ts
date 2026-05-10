export type SiteConfig = typeof siteConfig;

const isCloudEnv = process.env.NEXT_PUBLIC_IS_CLOUD_ENV === "true";

export const siteConfig = {
  name: isCloudEnv ? "Secto" : "Secto",
  description:
    "Secto is a cloud security platform for security visibility, assessments, dashboards, reports, and integrations across cloud environments.",
};
