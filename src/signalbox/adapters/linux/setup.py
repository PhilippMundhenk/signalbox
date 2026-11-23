"""What to run on a Linux device once so Signalbox can read it (shown in the device form).

``sudoers()`` must equal the rule in docs/adapters/linux.md (checked by a test), and the CI
container is prepared with ``commands()``, so what users paste is what is tested.
"""

from __future__ import annotations

from signalbox.adapters.linux.collect import WG_FIELDS

WG = "/usr/bin/wg"
SUDOERS_PATH = "/etc/sudoers.d/signalbox"


def sudoers_path(user: str = "signalbox") -> str:
    """The rule's file: one per login (``/etc/sudoers.d/signalbox`` for the default one)."""
    return f"/etc/sudoers.d/{user}"


#: Comment of the key the automatic setup installs (finds it again for a re-run or removal).
KEY_COMMENT = "signalbox-read"


def sudoers(user: str = "signalbox") -> str:
    """The sudoers rule for the WireGuard status: exactly the read commands, no password."""
    commands = ", ".join(f"{WG} show all {f}" for f in WG_FIELDS)
    return (
        "# Signalbox: read the WireGuard status. These commands print public keys only.\n"
        f"{user} ALL=(root) NOPASSWD: {commands}\n"
    )


def commands(user: str = "signalbox") -> str:
    """Shell commands for the device (Debian, Raspberry Pi OS, Ubuntu)."""
    return f"""# 1. a user of its own for Signalbox: no password, no sudo, no groups
sudo useradd --system --create-home --shell /bin/sh {user}
# 2. its login key: on your computer run  ssh-keygen -t ed25519 -N '' -f signalbox-key
#    paste the file signalbox-key into "Private key" below, and signalbox-key.pub here:
sudo install -d -m 700 -o {user} -g "$(id -gn {user})" ~{user}/.ssh
echo 'PASTE-THE-LINE-OF-signalbox-key.pub' | sudo tee ~{user}/.ssh/authorized_keys
sudo chown {user}: ~{user}/.ssh/authorized_keys && sudo chmod 600 ~{user}/.ssh/authorized_keys
#    (or instead a password:  sudo passwd {user})
# 3. optional, only with WireGuard: the read-only wg commands without a password
sudo tee {SUDOERS_PATH} >/dev/null <<'END'
{sudoers(user)}END
sudo chmod 440 {SUDOERS_PATH} && sudo visudo -cf {SUDOERS_PATH}
"""
