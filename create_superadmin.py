#!/usr/bin/env python3
"""Create the platform super admin (or reset its password) on an existing database.

  python create_superadmin.py <username>             create it (asks for the password)
  python create_superadmin.py <username> --reset     set a new password for an existing super admin

Run it from the project folder with the same SOC_MASTER_KEY the app uses.
The password is read from the keyboard (or from SOC_SUPERADMIN_PASSWORD) and is never printed."""
import getpass
import os
import sys

import db
import platform_admin


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    reset = "--reset" in sys.argv
    if len(args) != 1:
        print(__doc__)
        return 2
    pw = os.getenv("SOC_SUPERADMIN_PASSWORD") or getpass.getpass("New password (min 8 characters): ")
    if not os.getenv("SOC_SUPERADMIN_PASSWORD") and pw != getpass.getpass("Repeat password: "):
        print("The passwords do not match.")
        return 1
    db.init_db()
    try:
        import user_admin
        user_admin.init_user_admin_db()               # adds the columns the super admin row needs on an older database
    except Exception:
        pass
    try:
        result = platform_admin.ensure_superadmin(args[0], pw, reset=reset)
    except ValueError as exc:
        print(f"Not done: {exc}")
        return 1
    print({"created": f"Super admin '{args[0]}' created. Sign in with it and open the Tenants tab.",
           "reset": f"Password for '{args[0]}' was reset.",
           "exists": f"'{args[0]}' already exists. Run again with --reset to set a new password."}[result])
    return 0


if __name__ == "__main__":
    sys.exit(main())
