"""A remote adapter program for the tests: the Fake adapter of test_adapters, run by serve().

Behaviour switches come from the device settings (the program has no other input):
host "untrusted" / "auth" / "down" make it fail that way.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

from signalbox.adapters import AuthFailed, Unreachable, UntrustedCertificate
from signalbox.adapters.remote import serve
from test_adapters import Fake


class Program(Fake):
    async def read_system(self):  # type: ignore[no-untyped-def]
        host = self.context.config.host  # type: ignore[attr-defined]
        if host == "untrusted":
            raise UntrustedCertificate("ab" * 32, None)
        if host == "auth":
            raise AuthFailed("wrong password")
        if host == "down":
            raise Unreachable("no route")
        return await super().read_system()


raise SystemExit(serve(Program))
