"""AI Network Operations Assistant — CLI entry point (The Hands).

Security model:
- Identity is NEVER sourced from --user / --role CLI arguments.
- The caller is authenticated via engine.auth_provider.authenticate_current_user(),
  which reads from the environment (dev mode) or a trusted provider (production).
- An immutable UserContext is constructed once and passed through the entire pipeline.
- Authorization is validated against the authenticated UserContext BEFORE any device
  connection is attempted.
- Users cannot escalate their own privileges through any CLI argument.

Execution sequence:
  1. Authenticate → obtain immutable UserContext
  2. Resolve target device from inventory
  3. Validate authorization (UserContext.has_scope vs. requested classification)
  4. Build OperationRequest with authenticated context
  5. Execute via OperationsEngine
  6. Emit result
"""

import argparse
import sys
import os
import json
import uuid

# Ensure repository root is on sys.path
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from engine.auth_provider import authenticate_current_user, AuthenticationError, AuthorizationError
from engine.policy.types import TargetDevice, OperationRequest, OperationClassification, ExecutionMode
from engine.execution.operations_engine import OperationsEngine
from engine.inventory.inventory_manager import DeviceInventoryManager


def main() -> None:
    parser = argparse.ArgumentParser(
        description="AI Network Operations Assistant Executable Engine (The Hands)"
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Operational subcommands")

    # ------------------------------------------------------------------ #
    # inventory subcommand
    # ------------------------------------------------------------------ #
    parser_inv = subparsers.add_parser("inventory", help="List registered network devices")
    parser_inv.add_argument("--format", choices=["table", "json"], default="table")

    # ------------------------------------------------------------------ #
    # exec subcommand
    # NOTE: --user and --role are intentionally ABSENT.
    #       Identity comes from the authenticated session only.
    # ------------------------------------------------------------------ #
    parser_exec = subparsers.add_parser("exec", help="Execute an operation against a device")
    parser_exec.add_argument("--device", required=True, help="Target device ID or hostname")
    parser_exec.add_argument(
        "--action",
        default="system_info",
        choices=["system_info", "interfaces", "ping", "backup_config", "apply_config", "raw"],
    )
    parser_exec.add_argument("--command", help="Raw command to execute (READ_ONLY/DIAGNOSTIC only)")
    parser_exec.add_argument(
        "--classification",
        choices=["READ_ONLY", "DIAGNOSTIC", "WRITE", "CRITICAL"],
        default="READ_ONLY",
    )
    parser_exec.add_argument(
        "--mode",
        choices=["LIVE", "SIMULATED", "DRY_RUN"],
        default="SIMULATED",
    )
    # Legacy approval inputs are accepted for compatibility but are never
    # authorization evidence. WRITE/CRITICAL require an external verifier.
    parser_exec.add_argument(
        "--approve",
        action="store_true",
        help="Legacy flag; not accepted as authorization without external approval verification",
    )
    parser_exec.add_argument(
        "--token",
        help="External approval token (requires a configured trusted verifier)",
    )
    parser_exec.add_argument(
        "--param",
        action="append",
        help="Extra key=value parameters",
    )

    args = parser.parse_args()

    # ------------------------------------------------------------------ #
    # Step 1: Authenticate — before anything else
    # ------------------------------------------------------------------ #
    try:
        user_ctx = authenticate_current_user()
    except AuthenticationError as exc:
        print(f"AUTHENTICATION FAILED: {exc}", file=sys.stderr)
        sys.exit(2)
    except NotImplementedError as exc:
        print(f"AUTHENTICATION NOT CONFIGURED: {exc}", file=sys.stderr)
        sys.exit(2)

    inv_mgr = DeviceInventoryManager()

    # ------------------------------------------------------------------ #
    # inventory subcommand (read-only, any authenticated user)
    # ------------------------------------------------------------------ #
    if args.subcommand == "inventory":
        if not user_ctx.has_scope("READ_ONLY"):
            print("AUTHORIZATION FAILED: READ_ONLY scope required to list inventory.", file=sys.stderr)
            sys.exit(3)
        devs = inv_mgr.list_devices()
        if args.format == "json":
            print(json.dumps([d.__dict__ for d in devs], indent=2))
        else:
            print(f"{'DEVICE ID':<15} {'HOSTNAME':<25} {'VENDOR':<12} {'MODEL':<18} {'IP ADDRESS':<16} ENV")
            print("-" * 95)
            for d in devs:
                print(f"{d.device_id:<15} {d.hostname:<25} {d.vendor:<12} {d.model:<18} {d.ip_address:<16} {d.environment}")
        return

    # ------------------------------------------------------------------ #
    # exec subcommand
    # ------------------------------------------------------------------ #
    if args.subcommand == "exec":
        requested_classification = args.classification

        # Step 2: Verify the authenticated user has the required scope BEFORE
        #         resolving or touching the device.
        if not user_ctx.has_scope(requested_classification):
            print(
                f"AUTHORIZATION FAILED: User '{user_ctx.username}' (role: {user_ctx.role}) "
                f"lacks '{requested_classification}' scope.\n"
                "Authorized scopes: " + ", ".join(sorted(user_ctx.authorized_scopes)),
                file=sys.stderr,
            )
            sys.exit(3)

        # Development-mode guard: reject WRITE/CRITICAL even if the user mistakenly
        # has them in their scope (defense-in-depth; auth_provider already prevents this).
        if user_ctx.is_dev_mode and requested_classification in ("WRITE", "CRITICAL"):
            print(
                f"AUTHORIZATION FAILED: Development mode cannot execute "
                f"'{requested_classification}' operations.",
                file=sys.stderr,
            )
            sys.exit(3)

        # Step 3: Resolve device
        dev = inv_mgr.get_device(args.device)
        if not dev:
            print("TARGET REJECTED: Device is not registered in trusted inventory.", file=sys.stderr)
            sys.exit(4)

        # Step 4: Build extra parameters
        params: dict = {}
        if args.param:
            for p in args.param:
                if "=" in p:
                    k, v = p.split("=", 1)
                    params[k.strip()] = v.strip()

        # Step 5: Build OperationRequest — UserContext comes from authenticated session
        req = OperationRequest(
            request_id=f"OP-{uuid.uuid4().hex[:8].upper()}",
            user=user_ctx,          # immutable, authenticated context
            device=dev,
            classification=OperationClassification(requested_classification),
            action=args.action,
            command=args.command,
            parameters=params,
            execution_mode=ExecutionMode(args.mode),
            approved=args.approve,
            approval_token=args.token,
        )

        # Step 6: Execute
        engine = OperationsEngine()
        result = engine.execute(req)

        # Step 7: Emit result
        print(f"\n{'=' * 55}")
        print(f" EXECUTION REPORT: {result.request_id}")
        print(f" Status  : {'SUCCESS' if result.success else 'FAILED'}")
        print(f" Operator: {user_ctx.username} (role: {user_ctx.role})")
        print(f" Target  : {dev.hostname} ({dev.vendor} {dev.model})")
        print(f" Action  : {req.action} | Class: {result.classification.value} | Mode: {result.mode.value}")
        print(f" Time    : {result.execution_time_ms:.2f} ms")
        print("=" * 55)

        if result.error:
            print(f"ERROR: {result.error}")
        else:
            print("OUTPUT:")
            if isinstance(result.output, dict):
                print(json.dumps(result.output, indent=2))
            else:
                print(result.output)

        sys.exit(0 if result.success else 1)

    parser.print_help()


if __name__ == "__main__":
    main()
