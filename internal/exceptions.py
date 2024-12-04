class BaseClientException(Exception):
    """Base Exception for Clients."""


class NotFoundException(BaseClientException):
    """Not found exception."""


class RateLimitException(BaseClientException):
    """Rate limit exception."""
