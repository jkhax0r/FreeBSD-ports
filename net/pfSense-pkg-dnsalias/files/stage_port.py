"""Render the nine pkg-owned files into the port's staging directory."""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile


def digest(data):
    return hashlib.sha256(data).hexdigest()


def stage(payload, destination, version):
    package = Path(__file__).parent / "src" / "package"
    raw = payload.read_bytes()
    with zipfile.ZipFile(payload) as archive:
        manifest = json.loads(archive.read("MANIFEST.json"))
        if manifest["version"] != version:
            raise ValueError("runtime version differs from port version")

    gui = {
        name: (package / name).read_bytes()
        for name in ("gui.py", "registration.py", "registration_native.py", "setup_native.py")
    }
    templates = {
        "info.xml.in": "share/pfSense-pkg-dnsalias/info.xml",
        "dnsalias.xml.in": "pkg/dnsalias.xml",
        "dnsalias.inc": "pkg/dnsalias.inc",
    }
    catalog = {}
    for template, target in templates.items():
        body = (package / "catalog" / template).read_bytes()
        body = body.replace(b"@@PREFIX@@", b"/usr/local").replace(b"@@VERSION@@", version.encode())
        if b"@@" in body:
            raise ValueError(f"unresolved marker in {template}")
        catalog[target] = body

    bootstrap = (package / "bootstrap.py").read_bytes()
    for name, value in (
        ("GUI_SOURCES", {name: digest(data) for name, data in sorted(gui.items())}),
        ("GUI_RUNTIME_SHA256", digest(raw)),
        ("CATALOG_SOURCES", {name: digest(data) for name, data in sorted(catalog.items())}),
    ):
        assignment = f"{name} = None".encode()
        if bootstrap.count(assignment) != 1:
            raise ValueError(f"missing or duplicate bootstrap binding for {name}")
        bootstrap = bootstrap.replace(assignment, f"{name} = {value!r}".encode())

    files = {"share/dnsalias/bootstrap.py": bootstrap, "share/dnsalias/payload.zip": raw}
    files.update({f"share/dnsalias/gui/{name}": data for name, data in gui.items()})
    files.update(catalog)
    for name, data in files.items():
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        target.chmod(0o600)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("payload", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("version")
    args = parser.parse_args()
    stage(args.payload, args.destination, args.version)
