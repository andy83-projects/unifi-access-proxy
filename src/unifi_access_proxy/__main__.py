"""Entry point for python -m unifi_access_proxy."""

import asyncio
import logging
import signal
import sys

from .device import DeviceConfig
from .server import run_server


def setup_logging(level_name: str) -> None:
    level = getattr(logging, level_name.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def main() -> None:
    config = DeviceConfig.from_env()
    setup_logging(config.log_level)

    logger = logging.getLogger("unifi-access-proxy")
    logger.info("Starting UniFi Access Hub Proxy v0.1.0")
    logger.info(
        "Identity: Model=%s, Hostname=%s, MAC=%s, IP=%s, ID=%s",
        config.model,
        config.hostname,
        config.mac,
        config.advertised_ip,
        config.device_id,
    )
    logger.info("Active responses: %s", config.enable_active_responses)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    task = loop.create_task(run_server(config))

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, task.cancel)

    try:
        loop.run_until_complete(task)
    except asyncio.CancelledError:
        pass
    finally:
        loop.run_until_complete(loop.shutdown_asyncgens())
        loop.close()
        logger.info("Shutdown complete.")


if __name__ == "__main__":
    main()
