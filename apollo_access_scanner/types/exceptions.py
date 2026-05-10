"""Base exception classes for Apollo Access Scanner."""


class ApolloError(Exception):
    """Base exception for Apollo Access Scanner."""

    pass


class ProviderError(ApolloError):
    """Exception for cloud provider errors."""

    pass


class CredentialsError(ApolloError):
    """Exception for credential-related errors."""

    pass
