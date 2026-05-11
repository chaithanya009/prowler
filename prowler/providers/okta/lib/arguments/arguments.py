SENSITIVE_ARGUMENTS = frozenset({"--okta-api-token"})


def init_parser(self):
    """Init the Okta provider CLI parser."""
    okta_parser = self.subparsers.add_parser(
        "okta",
        parents=[self.common_providers_parser],
        help="Okta Provider",
    )

    auth_group = okta_parser.add_argument_group("Authentication")
    auth_group.add_argument(
        "--okta-org-url",
        nargs="?",
        default=None,
        metavar="OKTA_ORG_URL",
        help="Okta org URL. Use OKTA_ORG_URL env var when possible.",
    )
    auth_group.add_argument(
        "--okta-api-token",
        nargs="?",
        default=None,
        metavar="OKTA_API_TOKEN",
        help="Okta API token. Use OKTA_API_TOKEN env var instead of passing directly.",
    )


def validate_arguments(_arguments):
    return (True, "")
