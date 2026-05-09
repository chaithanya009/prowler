import { IntegrationType } from "../types/integrations";

// Documentation URLs
export const DOCS_URLS = {
  FINDINGS_ANALYSIS: "https://secto.io/docs",
  AWS_ORGANIZATIONS: "https://secto.io/docs",
  ATTACK_PATHS_CUSTOM_QUERIES: "https://secto.io/docs",
} as const;

// CloudFormation template URL for the SectoScan role.
// Also used (URL-encoded) as the templateURL param in cloudformationQuickLink
// and cloudformationOrgQuickLink below — keep both in sync.
export const PROWLER_CF_TEMPLATE_URL =
  "https://prowler-cloud-public.s3.eu-west-1.amazonaws.com/permissions/templates/aws/cloudformation/prowler-scan-role.yml";

// AWS Console URL for creating a new StackSet.
// Hardcoded to us-east-1 — StackSets are typically managed from this region.
// Users in AWS GovCloud or China partitions would need different URLs.
export const STACKSET_CONSOLE_URL =
  "https://us-east-1.console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacksets/create";

export const getProviderHelpText = (provider: string) => {
  switch (provider) {
    case "aws":
      return {
        text: "Need help connecting your AWS account?",
        link: "https://secto.io/docs",
      };
    case "azure":
      return {
        text: "Need help connecting your Azure subscription?",
        link: "https://secto.io/docs",
      };
    case "m365":
      return {
        text: "Need help connecting your Microsoft 365 account?",
        link: "https://secto.io/docs",
      };
    case "gcp":
      return {
        text: "Need help connecting your GCP project?",
        link: "https://secto.io/docs",
      };
    case "kubernetes":
      return {
        text: "Need help connecting your Kubernetes cluster?",
        link: "https://secto.io/docs",
      };
    case "github":
      return {
        text: "Need help connecting your GitHub account?",
        link: "https://secto.io/docs",
      };
    case "iac":
      return {
        text: "Need help scanning your Infrastructure as Code repository?",
        link: "https://secto.io/docs",
      };
    case "image":
      return {
        text: "Need help scanning your container registry?",
        link: "https://secto.io/docs",
      };
    case "oraclecloud":
      return {
        text: "Need help connecting your Oracle Cloud account?",
        link: "https://secto.io/docs",
      };
    case "mongodbatlas":
      return {
        text: "Need help connecting your MongoDB Atlas organization?",
        link: "https://secto.io/docs",
      };
    case "alibabacloud":
      return {
        text: "Need help connecting your Alibaba Cloud account?",
        link: "https://secto.io/docs",
      };
    case "cloudflare":
      return {
        text: "Need help connecting your Cloudflare account?",
        link: "https://secto.io/docs",
      };
    case "openstack":
      return {
        text: "Need help connecting your OpenStack cloud?",
        link: "https://secto.io/docs",
      };
    case "googleworkspace":
      return {
        text: "Need help connecting your Google Workspace account?",
        link: "https://secto.io/docs",
      };
    case "vercel":
      return {
        text: "Need help connecting your Vercel team?",
        link: "https://secto.io/docs",
      };
    default:
      return {
        text: "How to setup a provider?",
        link: "https://secto.io/docs",
      };
  }
};

export const getAWSCredentialsTemplateLinks = (
  externalId: string,
  bucketName?: string,
  integrationType?: IntegrationType,
): {
  cloudformation: string;
  terraform: string;
  cloudformationQuickLink: string;
  cloudformationOrgQuickLink: string;
} => {
  let links = {};

  if (integrationType === undefined || integrationType === "aws_security_hub") {
    links = {
      cloudformation: "https://secto.io/docs",
      terraform: "https://secto.io/docs",
    };
  }

  if (integrationType === "amazon_s3") {
    links = {
      cloudformation: "https://secto.io/docs",
      terraform: "https://secto.io/docs",
    };
  }

  const encodedTemplateUrl = encodeURIComponent(PROWLER_CF_TEMPLATE_URL);
  const cfBaseUrl =
    "https://us-east-1.console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/quickcreate";
  const s3Params = bucketName
    ? `&param_EnableS3Integration=true&param_S3IntegrationBucketName=${bucketName}`
    : "";

  return {
    ...(links as {
      cloudformation: string;
      terraform: string;
    }),
    cloudformationQuickLink:
      `${cfBaseUrl}?templateURL=${encodedTemplateUrl}` +
      `&stackName=Secto&param_ExternalId=${externalId}${s3Params}`,
    cloudformationOrgQuickLink:
      `${cfBaseUrl}?templateURL=${encodedTemplateUrl}` +
      `&stackName=Secto&param_ExternalId=${externalId}` +
      `&param_EnableOrganizations=true${s3Params}`,
  };
};
