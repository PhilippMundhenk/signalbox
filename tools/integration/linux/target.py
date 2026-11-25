"""Start and stop the Linux integration target (#240): a Debian container (11, 12 or 13) with sshd.

    DEBIAN=11 python tools/integration/linux/target.py start DIR   # 11, 12 (default) or 13
    python tools/integration/linux/target.py start DIR   # build, run, create the read user
    python tools/integration/linux/target.py stop DIR

``start`` creates the read user ``signalbox`` with the commands of the setup guide
(``signalbox.adapters.linux.setup.commands()``, the key line replaced by a key generated into
DIR) and writes the IT_LINUX_* variables to ``$GITHUB_ENV`` (or prints them).
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
NAME = "signalbox-linux"
IMAGE = "signalbox-linux-target"
PORT = 2222
ROOT_PASSWORD = "it-root-password-1"
ADMIN_USER = "admin"
ADMIN_PASSWORD = "it-admin-password-1"
#: the Debian major version of the container (#417): 11, 12 or 13
DEBIAN = os.environ.get("DEBIAN", "12")


def sh(*args: str, check: bool = True, **kw: object) -> subprocess.CompletedProcess[str]:
    print("+", " ".join(args), flush=True)
    return subprocess.run(args, check=check, text=True, **kw)  # type: ignore[call-overload]


def start(work: Path) -> None:
    from signalbox.adapters.linux.setup import commands

    work.mkdir(parents=True, exist_ok=True)
    sh("sudo", "modprobe", "-a", "dummy", "8021q", "bridge", "wireguard")
    # nftables in the container uses the host's kernel modules (a missing one: the test shows it)
    for module in (
        "nf_tables",
        "nft_ct",
        "nft_nat",
        "nft_masq",
        "nft_chain_nat",
        "nf_nat",
        # the legacy iptables backend (iptables-legacy alternative, #394)
        "ip_tables",
        "iptable_filter",
        "iptable_nat",
        "ip6_tables",
        "ip6table_filter",
        "xt_conntrack",
        "xt_comment",
        "xt_multiport",
        "xt_tcpudp",
        "xt_MASQUERADE",
        "xt_nat",
    ):
        sh("sudo", "modprobe", module, check=False)
    sh("docker", "build", "--build-arg", f"DEBIAN={DEBIAN}", "-t", IMAGE, str(HERE))
    sh("docker", "rm", "-f", NAME, check=False, capture_output=True)
    sh(
        "docker",
        "run",
        "-d",
        "--name",
        NAME,
        "--cap-add",
        "NET_ADMIN",
        "--sysctl",
        "net.ipv6.conf.all.disable_ipv6=0",
        "-e",
        f"ROOT_PASSWORD={ROOT_PASSWORD}",
        "-e",
        f"ADMIN_USER={ADMIN_USER}",
        "-e",
        f"ADMIN_PASSWORD={ADMIN_PASSWORD}",
        "-p",
        f"127.0.0.1:{PORT}:22",
        IMAGE,
    )
    for _ in range(60):
        if sh("docker", "exec", NAME, "test", "-e", "/ready", check=False).returncode == 0:
            break
        time.sleep(1)
    else:
        sh("docker", "logs", NAME, check=False)
        raise SystemExit("the container did not get ready")
    key = work / "signalbox-key"
    key.unlink(missing_ok=True)
    Path(f"{key}.pub").unlink(missing_ok=True)
    sh("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "it", "-f", str(key))
    public = Path(f"{key}.pub").read_text().strip()
    script = commands().replace("PASTE-THE-LINE-OF-signalbox-key.pub", public)
    sh("docker", "exec", "-i", NAME, "bash", "-e", "-s", input=script)
    wg_public = sh("docker", "exec", NAME, "cat", "/wg0.pub", capture_output=True).stdout.strip()
    host_key = sh(
        "docker",
        "exec",
        NAME,
        "ssh-keygen",
        "-lf",
        "/etc/ssh/ssh_host_ed25519_key.pub",
        capture_output=True,
    ).stdout.split()[1]
    env = {
        "IT_LINUX_URL": f"ssh://127.0.0.1:{PORT}",
        "IT_LINUX_USER": "signalbox",
        "IT_LINUX_KEY_FILE": str(key),
        "IT_LINUX_ROOT_PASSWORD": ROOT_PASSWORD,
        "IT_LINUX_ADMIN_USER": ADMIN_USER,
        "IT_LINUX_ADMIN_PASSWORD": ADMIN_PASSWORD,
        "IT_LINUX_CONTAINER": NAME,
        "IT_LINUX_DEBIAN": DEBIAN,
        "IT_LINUX_WG_PUBLIC": wg_public,
        "IT_LINUX_HOST_KEY": host_key,
    }
    lines = "".join(f"{k}={v}\n" for k, v in env.items())
    target = os.environ.get("GITHUB_ENV")
    if target:
        with open(target, "a") as fh:
            fh.write(lines)
    print(lines)


def stop(work: Path) -> None:
    logs = sh("docker", "logs", NAME, check=False, capture_output=True)
    work.mkdir(parents=True, exist_ok=True)
    (work / "container.log").write_text((logs.stdout or "") + (logs.stderr or ""))
    sh("docker", "rm", "-f", NAME, check=False)


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in ("start", "stop"):
        raise SystemExit(__doc__)
    {"start": start, "stop": stop}[sys.argv[1]](Path(sys.argv[2]))
