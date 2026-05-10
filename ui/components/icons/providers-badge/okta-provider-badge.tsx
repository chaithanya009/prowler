import { IconSvgProps } from "@/types";

export const OktaProviderBadge: React.FC<IconSvgProps> = ({
  size,
  width,
  height,
  ...props
}) => (
  <svg
    xmlns="http://www.w3.org/2000/svg"
    aria-hidden="true"
    fill="none"
    focusable="false"
    height={size || height}
    role="presentation"
    viewBox="0 0 256 256"
    width={size || width}
    {...props}
  >
    <rect width="256" height="256" rx="60" fill="#00297a" />
    <circle cx="128" cy="128" r="64" fill="#ffffff" />
    <circle cx="128" cy="128" r="34" fill="#00297a" />
  </svg>
);
