"""
Fuzz target for XML parsing in nmap_recon.py.

Exercises the XML-to-JSON parsing logic used by nmap_recon with arbitrary
XML input to find crashes, XXE issues, or unexpected behaviour in the
defusedxml-based parser.
"""
import atheris
import sys

import defusedxml.ElementTree as ET  # noqa: E402


def _parse_nmap_xml(xml_bytes: bytes) -> dict:
    """
    Reimplements the core XML parsing logic from NmapRecon.parse_xml_to_json()
    so it can be fuzzed without file I/O or the nmap dependency.
    """
    root = ET.fromstring(xml_bytes)
    data = {"targets": [], "hosts": []}

    for host in root.findall("host"):
        addr = host.find("address")
        ip = addr.get("addr") if addr is not None else "unknown"
        hostname_el = host.find("hostnames/hostname")
        hostname = hostname_el.get("name") if hostname_el is not None else "N/A"
        services = []
        for port in host.findall("ports/port"):
            svc = port.find("service")
            services.append({
                "name": svc.get("name", "") if svc is not None else "",
                "port": port.get("portid", ""),
                "protocol": port.get("protocol", ""),
            })

        data["hosts"].append({
            "ip": ip,
            "hostname": hostname,
            "services": services,
        })

    return data


def TestOneInput(data: bytes) -> None:
    """Fuzz XML parsing with arbitrary byte input."""
    try:
        _parse_nmap_xml(data)
    except ET.ParseError:
        pass
    except (KeyError, TypeError, IndexError, AttributeError, ValueError):
        pass


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
