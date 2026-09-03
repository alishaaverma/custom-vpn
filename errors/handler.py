import logging


def log_exception(context: str, exc: BaseException) -> None:
    logging.getLogger("vpn").exception("%s: %s", context, exc)
