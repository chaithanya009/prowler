from prowler.exceptions.exceptions import ProwlerException


class OktaBaseException(ProwlerException):
    """Base exception for Okta provider errors."""

    OKTA_ERROR_CODES = {
        (14000, "OktaCredentialsError"): {
            "message": "Okta credentials were not found or are invalid.",
            "remediation": "Set OKTA_ORG_URL and OKTA_API_TOKEN, or pass them through the Okta provider arguments.",
        },
        (14001, "OktaAuthenticationError"): {
            "message": "Authentication to Okta failed.",
            "remediation": "Verify the Okta org URL and API token permissions.",
        },
        (14002, "OktaSessionError"): {
            "message": "Failed to create an Okta API session.",
            "remediation": "Check network connectivity and ensure the Okta org URL is reachable.",
        },
        (14003, "OktaIdentityError"): {
            "message": "Failed to retrieve Okta identity information.",
            "remediation": "Ensure the API token can read the current user.",
        },
        (14004, "OktaAPIError"): {
            "message": "An error occurred while calling the Okta API.",
            "remediation": "Check the Okta API response and retry the request.",
        },
        (14005, "OktaRateLimitError"): {
            "message": "Rate limited by the Okta API.",
            "remediation": "Wait and retry the request.",
        },
    }

    def __init__(self, code, file=None, original_exception=None, message=None):
        error_info = self.OKTA_ERROR_CODES.get((code, self.__class__.__name__))
        if error_info is None:
            error_info = {
                "message": message or "Unknown Okta error.",
                "remediation": "Check the Okta API documentation for more details.",
            }
        elif message:
            error_info = error_info.copy()
            error_info["message"] = message
        super().__init__(
            code=code,
            source="Okta",
            file=file,
            original_exception=original_exception,
            error_info=error_info,
        )


class OktaCredentialsError(OktaBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            14000, file=file, original_exception=original_exception, message=message
        )


class OktaAuthenticationError(OktaBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            14001, file=file, original_exception=original_exception, message=message
        )


class OktaSessionError(OktaBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            14002, file=file, original_exception=original_exception, message=message
        )


class OktaIdentityError(OktaBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            14003, file=file, original_exception=original_exception, message=message
        )


class OktaAPIError(OktaBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            14004, file=file, original_exception=original_exception, message=message
        )


class OktaRateLimitError(OktaBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            14005, file=file, original_exception=original_exception, message=message
        )
