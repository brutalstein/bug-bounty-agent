from __future__ import annotations

import argparse

from app.commands.shared import load_scope, print_fail, print_info, print_ok
from core.lab_manager import LabManager


def command_lab_status(args: argparse.Namespace) -> int:
    scope = load_scope(args.profile)
    manager = LabManager(scope)
    status = manager.status()

    print_info("Lab status:")
    print(f"Profile:            {status.profile_name}")
    print(f"Container name:     {status.container_name}")
    print(f"Docker image:       {status.docker_image}")
    print(f"Published port:     {status.published_port}")
    print(f"Container port:     {status.container_port}")
    print(f"Docker available:   {status.docker_available}")
    print(f"Container present:  {status.container_present}")
    print(f"Container running:  {status.container_running}")
    print(f"HTTP reachable:     {status.reachable_over_http}")
    print(f"HTTP status code:   {status.http_status_code}")
    print(f"Docker status:      {status.docker_status_text}")

    if status.error:
        print_fail(f"Lab status error: {status.error}")

    return 0 if status.container_running or status.reachable_over_http else 1


def command_lab_up(args: argparse.Namespace) -> int:
    scope = load_scope(args.profile)
    manager = LabManager(scope)
    ok, message = manager.up()

    if ok:
        print_ok("Lab startup command completed.")
        print_info(message)
        return 0

    print_fail(message)
    return 1


def command_lab_down(args: argparse.Namespace) -> int:
    scope = load_scope(args.profile)
    manager = LabManager(scope)
    ok, message = manager.down()

    if ok:
        print_ok("Lab shutdown command completed.")
        print_info(message)
        return 0

    print_fail(message)
    return 1
