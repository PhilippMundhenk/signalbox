"""What to run on a Linux device once so Signalbox can read it (shown in the device form).

``sudoers()`` must equal the rule in docs/adapters/linux.md (checked by a test), and the CI
container is prepared with ``commands()``, so what users paste is what is tested.
"""

from __future__ import annotations

from signalbox.adapters.linux.collect import (
    CAT,
    DDNS_SUDO_FILES,
    IP6TABLES_SAVE,
    IPTABLES_SAVE,
    NFT,
    NFT_ARGS,
    WG_FIELDS,
)

WG = "/usr/bin/wg"
SUDOERS_PATH = "/etc/sudoers.d/signalbox"


def sudoers_path(user: str = "signalbox") -> str:
    """The rule's file: one per login (``/etc/sudoers.d/signalbox`` for the default one)."""
    return f"/etc/sudoers.d/{user}"


#: Comment of the key the automatic setup installs (finds it again for a re-run or removal).
KEY_COMMENT = "signalbox-read"


def sudo_commands() -> list[str]:
    """Every command the sudoers rule allows: the one list that builds the rule and the texts of
    the setup steps (#499), so that they cannot drift apart."""
    return [
        *(f"{WG} show all {f}" for f in WG_FIELDS),
        f"{NFT} {NFT_ARGS}",
        f'{IPTABLES_SAVE} ""',
        f'{IP6TABLES_SAVE} ""',
        *(f"{CAT} {path}" for path in DDNS_SUDO_FILES),
    ]


#: The tools whose presence makes the setup write the rule (wg, nft, iptables-save, ddclient or
#: inadyn), for the step that says why there is none.
SUDO_TOOLS = "wg, nft, iptables-save, ddclient, inadyn"


def sudoers(user: str = "signalbox") -> str:
    """The sudoers rule: exactly the read commands (``wg show all <field>``, nft, and
    ``iptables-save`` / ``ip6tables-save`` with an empty argument list, and ``cat`` of the two
    dynamic DNS configuration files, whose credential lines the read script removes on the
    device, #450), no password."""
    commands = ", ".join(sudo_commands())
    return (
        "# Signalbox: read the WireGuard status (public keys only), the nftables ruleset and the\n"
        "# legacy iptables rules (iptables-save without arguments), and the dynamic DNS\n"
        "# configuration files of ddclient and inadyn (read through a filter that drops the\n"
        "# password and token lines on the device).\n"
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
# 3. optional, only with WireGuard, nftables or iptables: the read-only commands without a password
sudo tee {SUDOERS_PATH} >/dev/null <<'END'
{sudoers(user)}END
sudo chmod 440 {SUDOERS_PATH} && sudo visudo -cf {SUDOERS_PATH}
"""
