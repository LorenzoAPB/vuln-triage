"""Write evals/cwe_parents.json: each CWE's direct parents (ChildOf) in MITRE's Research view (1000).

Used only for the lenient "parent or child" CWE metric. Run: python -m evals.build_cwe_tree
"""

import io
import json
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
NS = {"cwe": "http://cwe.mitre.org/cwe-8"}


def main() -> None:
    with urllib.request.urlopen(URL, timeout=120) as response:
        archive = zipfile.ZipFile(io.BytesIO(response.read()))
    root = ET.fromstring(archive.read(archive.namelist()[0]))
    parents = {}
    for weakness in root.iterfind("cwe:Weaknesses/cwe:Weakness", NS):
        related = weakness.iterfind("cwe:Related_Weaknesses/cwe:Related_Weakness", NS)
        ids = sorted(
            {f"CWE-{r.get('CWE_ID')}" for r in related if r.get("Nature") == "ChildOf" and r.get("View_ID") == "1000"}
        )
        parents[f"CWE-{weakness.get('ID')}"] = ids
    out = {"source": URL, "cwe_version": root.get("Version"), "cwe_date": root.get("Date"), "parents": parents}
    path = Path(__file__).parent / "cwe_parents.json"
    path.write_text(json.dumps(out, indent=0, sort_keys=True) + "\n")
    print(f"wrote {len(parents)} weaknesses (CWE {out['cwe_version']}) to {path}")


if __name__ == "__main__":
    main()
