"""Exception types for the keyrotate library."""


class KeyRotateError(Exception):
    """Base class for all keyrotate errors."""


class RecordNotFound(KeyRotateError):
    """The requested record or version does not exist."""


class RotationInProgress(KeyRotateError):
    """A different rotation round is currently active."""


class StaleRotationId(KeyRotateError):
    """The rotation id belongs to an older, already superseded round."""


class MasterKeyError(KeyRotateError):
    """Master key material is missing, corrupt, or inconsistent."""
