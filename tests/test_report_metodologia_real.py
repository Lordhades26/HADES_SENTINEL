"""El DOCX debe describir el escaneo ejecutado sin atribuir explotación ficticia."""

import os
import sys
import tempfile
import unittest

from docx import Document

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from hades_report_docx import build_iso27001_docx


class TestMetodologiaDelInforme(unittest.TestCase):
    def test_docx_usa_iso_como_referencia_y_no_inventa_explotacion(self):
        data = {
            "subnet": "192.0.2.0/24", "date": "16/10/2026", "devices": "0",
            "hosts": [], "tools": {"Nmap": True, "Tshark": True, "Nuclei": True,
                                  "OpenSSL": True, "Ollama": True},
            "traffic_summary": "", "traffic_ai": "",
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "informe.docx")
            build_iso27001_docx(data, path)
            doc = Document(path)
            content = "\n".join(
                [p.text for p in doc.paragraphs] +
                [cell.text for table in doc.tables for row in table.rows for cell in row.cells]
            )

        self.assertIn("ISO/IEC 27001", content)
        self.assertIn("referencia", content.lower())
        self.assertIn("Nmap", content)
        self.assertIn("Nuclei", content)
        self.assertIn("No se detectaron activos evaluables", content)
        self.assertNotIn("nivel de riesgo global es BAJO", content)
        for invented in ("Conforme a", "Metasploit", "msfvenom", "Meterpreter",
                         "auditoría interna autorizada por la dirección"):
            self.assertNotIn(invented, content)


if __name__ == "__main__":
    unittest.main()
