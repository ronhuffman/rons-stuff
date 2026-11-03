"""An in-memory stand-in for ``winreg``, so registry code can be tested on any
machine without touching a real registry.

It copies the constants of the module it replaces, so hive maps built from
that module at import time keep working, and it mimics the behaviours the code
under test depends on: missing keys raise FileNotFoundError, enumeration ends
with OSError, DeleteKey refuses a key that still has subkeys, and a closed
handle cannot be used.
"""

from __future__ import annotations


class _Node:
    def __init__(self) -> None:
        self.values: dict[str, tuple[str, object, int]] = {}
        self.keys: dict[str, tuple[str, "_Node"]] = {}


class _Handle:
    def __init__(self, node: _Node, path: str = "") -> None:
        self.node = node
        self.path = path.lower()
        self.closed = False

    def _live(self) -> _Node:
        if self.closed:
            raise OSError(6, "The handle is invalid")
        return self.node

    def Close(self) -> None:
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        self.Close()


class FakeWinreg:
    def __init__(self, real) -> None:
        for name in dir(real):
            if name.isupper():
                setattr(self, name, getattr(real, name))
        self.error = OSError
        self.roots: dict[object, _Node] = {}
        #: lower-case subkey paths that OpenKey refuses, to simulate denial
        self.denied: set[str] = set()
        #: lower-case subkey path -> error raised by EnumKey/EnumValue after
        #: the first item, to simulate an enumeration that fails part-way
        self.enum_errors: dict[str, OSError] = {}

    # ---- navigation ------------------------------------------------------
    @staticmethod
    def _join(key, sub: str) -> str:
        parts = [key.path] if isinstance(key, _Handle) and key.path else []
        parts += [p for p in (sub or "").split("\\") if p]
        return "\\".join(parts)

    def _base(self, key) -> _Node:
        if isinstance(key, _Handle):
            return key._live()
        return self.roots.setdefault(key, _Node())

    def _walk(self, key, sub: str, create: bool) -> _Node:
        node = self._base(key)
        for part in [p for p in (sub or "").split("\\") if p]:
            hit = node.keys.get(part.lower())
            if hit is None:
                if not create:
                    raise FileNotFoundError(2, "The system cannot find the file specified")
                hit = (part, _Node())
                node.keys[part.lower()] = hit
            node = hit[1]
        return node

    # ---- winreg API ------------------------------------------------------
    def OpenKey(self, key, sub, reserved=0, access=0):
        if (sub or "").lower() in self.denied:
            raise PermissionError(5, "Access is denied")
        return _Handle(self._walk(key, sub, create=False), self._join(key, sub))

    OpenKeyEx = OpenKey

    def CreateKeyEx(self, key, sub, reserved=0, access=0):
        return _Handle(self._walk(key, sub, create=True), self._join(key, sub))

    def CreateKey(self, key, sub):
        return self.CreateKeyEx(key, sub)

    def CloseKey(self, h) -> None:
        h.Close()

    def _maybe_fail(self, h, i) -> None:
        err = self.enum_errors.get(h.path)
        if err is not None and i >= 1:
            raise err

    def EnumKey(self, h, i):
        self._maybe_fail(h, i)
        names = [n for n, _ in h._live().keys.values()]
        if i >= len(names):
            raise OSError(259, "No more data is available")
        return names[i]

    def EnumValue(self, h, i):
        self._maybe_fail(h, i)
        vals = list(h._live().values.values())
        if i >= len(vals):
            raise OSError(259, "No more data is available")
        return vals[i]

    def QueryValueEx(self, h, name):
        hit = h._live().values.get((name or "").lower())
        if hit is None:
            raise FileNotFoundError(2, "The system cannot find the file specified")
        return hit[1], hit[2]

    def SetValueEx(self, h, name, reserved, typ, data):
        h._live().values[(name or "").lower()] = (name or "", data, typ)

    def DeleteValue(self, h, name):
        node = h._live()
        if (name or "").lower() not in node.values:
            raise FileNotFoundError(2, "The system cannot find the file specified")
        del node.values[(name or "").lower()]

    def DeleteKey(self, key, sub):
        parts = [p for p in sub.split("\\") if p]
        parent = self._walk(key, "\\".join(parts[:-1]), create=False)
        hit = parent.keys.get(parts[-1].lower())
        if hit is None:
            raise FileNotFoundError(2, "The system cannot find the file specified")
        if hit[1].keys:
            raise PermissionError(5, "Access is denied")
        del parent.keys[parts[-1].lower()]

    # ---- test helpers ----------------------------------------------------
    def exists(self, key, sub: str) -> bool:
        try:
            self._walk(key, sub, create=False)
            return True
        except FileNotFoundError:
            return False

    def dump(self, key, sub: str) -> dict:
        node = self._walk(key, sub, create=False)
        return {"values": {n: (d, t) for n, d, t in node.values.values()},
                "keys": {n: self.dump(node_key, "") for n, node_key in
                         ((n, _Handle(child)) for n, child in node.keys.values())}}
