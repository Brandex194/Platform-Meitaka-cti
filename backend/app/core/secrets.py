import json
import logging
import os

import httpx

logger = logging.getLogger(__name__)


def _from_vault(key: str, addr: str) -> str:
    # shortcut: fixed KV v2 path secret/data/sentinel, no retry; upgrade if per-key paths are needed
    resp = httpx.get(
        f"{addr.rstrip('/')}/v1/secret/data/sentinel",
        headers={"X-Vault-Token": os.getenv("VAULT_TOKEN", "")},
        timeout=5.0,
    )
    resp.raise_for_status()
    return resp.json()["data"]["data"].get(key) or ""


def _from_aws(key: str, arn: str) -> str:
    # boto3 is not a project dependency; a missing install falls through to the warning path
    import boto3  # noqa: PLC0415

    raw = boto3.client("secretsmanager").get_secret_value(SecretId=arn)["SecretString"]
    return json.loads(raw).get(key) or ""


def resolve_secret(key: str) -> str:
    value = os.getenv(key)
    if value:
        return value

    try:
        if addr := os.getenv("VAULT_ADDR"):
            value = _from_vault(key, addr)
        if not value and (arn := os.getenv("AWS_SECRET_ARN")):
            value = _from_aws(key, arn)
    except Exception as exc:
        logger.warning("secret %s lookup failed: %s", key, exc)
        value = ""

    if value:
        return value

    logger.warning("secret %s not found, using empty string", key)
    return ""
