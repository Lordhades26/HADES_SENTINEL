"""Tests de aprobación (golden master) sin dependencias externas.

Cada caso convierte una salida determinista en texto y la compara con
`tests/approved/<nombre>.approved.txt`.

- Si coincide: el test pasa.
- Si no coincide o no existe: se escribe `<nombre>.received.txt` al lado y el
  test falla mostrando el diff. Una persona revisa el diff y, si el cambio es
  correcto, lo aprueba:

      set HADES_APPROVE=1 && python tests/run_all.py      (cmd)
      $env:HADES_APPROVE=1; python tests/run_all.py      (PowerShell)

  o renombrando a mano el `.received.txt` a `.approved.txt`.

Los `.received.txt` no se versionan (ver .gitignore); los `.approved.txt` sí:
son la especificación del comportamiento observable de SENTINEL.
"""
import difflib
import json
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
APPROVED_DIR = os.path.join(_HERE, "approved")


def _normalizar(texto):
    # Fin de línea estable entre Windows/Linux y siempre con \n final.
    return texto.replace("\r\n", "\n").rstrip("\n") + "\n"


def como_texto(valor):
    """Serializa un valor de forma estable y legible para el golden."""
    if isinstance(valor, str):
        return valor
    return json.dumps(valor, ensure_ascii=False, indent=2, sort_keys=True, default=str)


def verify(testcase, nombre, valor):
    """Compara `valor` con el golden `nombre`; falla con diff si difiere."""
    os.makedirs(APPROVED_DIR, exist_ok=True)
    recibido = _normalizar(como_texto(valor))
    aprobado_path = os.path.join(APPROVED_DIR, f"{nombre}.approved.txt")
    recibido_path = os.path.join(APPROVED_DIR, f"{nombre}.received.txt")

    if os.environ.get("HADES_APPROVE", "").strip() == "1":
        with open(aprobado_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(recibido)
        if os.path.exists(recibido_path):
            os.remove(recibido_path)
        return

    aprobado = None
    if os.path.exists(aprobado_path):
        with open(aprobado_path, encoding="utf-8") as f:
            aprobado = _normalizar(f.read())

    if aprobado == recibido:
        if os.path.exists(recibido_path):
            os.remove(recibido_path)
        return

    with open(recibido_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(recibido)
    if aprobado is None:
        testcase.fail(f"Sin golden aprobado para '{nombre}'. Revisar {recibido_path} "
                      "y aprobar con HADES_APPROVE=1.")
    diff = "".join(difflib.unified_diff(
        aprobado.splitlines(True), recibido.splitlines(True),
        fromfile=f"{nombre}.approved.txt", tofile=f"{nombre}.received.txt"))
    testcase.fail(f"La salida de '{nombre}' cambió respecto del golden aprobado:\n{diff}")
