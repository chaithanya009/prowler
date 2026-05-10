import { ApiError, ProviderProps } from "@/types";

export interface AddProviderResponse {
  data?: unknown;
  error?: string;
  errors?: ApiError[];
  status?: number;
  success?: boolean;
}

export function getCreatedProvider(
  response: AddProviderResponse | undefined,
): ProviderProps | null {
  const provider = response?.data;

  if (!provider || typeof provider !== "object") {
    return null;
  }

  if (!("id" in provider) || !("attributes" in provider)) {
    return null;
  }

  return provider as ProviderProps;
}

export function getAddProviderErrorMessage(
  response: AddProviderResponse | undefined,
): string | null {
  if (response?.error) {
    return response.error;
  }

  if (!getCreatedProvider(response)) {
    return "The provider could not be created. Please try again.";
  }

  return null;
}
