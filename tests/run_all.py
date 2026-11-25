#!/usr/bin/env python3
"""
Runner unico de la suite de HADES SENTINEL.

Motivo: la suite convive en DOS estilos y ningun comando los ejecutaba todos.
  - tests/test_hades_sentinel.py  -> funciones test_* con assert (estilo pytest)
  - tests/test_*.py (los demas)   -> clases unittest.TestCase

`python -m unittest discover -s tests` solo descubre las clases TestCase, asi que
omitia en SILENCIO los 13 casos funcionales (entre ellos SEC-02, SEC-07, SEC-08 y
SEC-09). Quien verificaba la build con ese comando obtenia un OK que no cubria la
mitad de la suite.

Este runner ejecuta AMBOS estilos, sin depender de pytest: el agente esta pensado
para operar en redes aisladas, donde no se puede instalar nada con pip.

Uso:
    python tests/run_all.py          # todo
    python tests/run_all.py -v       # detalle de los casos unittest

Codigo de salida: 0 solo si TODOS los casos pasan.
"""
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for _p in (_ROOT, _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)


def _ejecutar_estilo_funciones():
    """Corre tests/test_hades_sentinel.py con su runner propio.

    Un fallo al importar NO se silencia: sin esto volveriamos al problema
    original, en el que la mitad de la suite desaparecia sin aviso.
    """
    print("\n" + "=" * 74)
    print(" BLOQUE 1/2 — casos funcionales, seguridad, integracion y rendimiento")
    print("=" * 74)
    try:
        import test_hades_sentinel as suite
    except Exception as e:
        print(f"[ERROR] no se pudo importar test_hades_sentinel: "
              f"{e.__class__.__name__}: {e}")
        print("        La suite funcional NO se ejecuto. Se cuenta como fallo.")
        return None, 1
    fallos = suite._run_all()
    total = len([n for n in dir(suite) if n.startswith("test_")])
    return total, fallos


def _ejecutar_estilo_unittest(verbosidad):
    """Corre las clases unittest.TestCase del directorio tests/."""
    print("\n" + "=" * 74)
    print(" BLOQUE 2/2 — regresiones de la Fase 4 y grounding del analisis IA")
    print("=" * 74)
    cargador = unittest.TestLoader()
    # Sin top_level_dir: tests/ no es un paquete (no hay __init__.py) y unittest
    # exigiria que lo fuera. Cada test ya se agrega la raiz al sys.path.
    suite = cargador.discover(_HERE, pattern="test_*.py")
    resultado = unittest.TextTestRunner(verbosity=verbosidad).run(suite)
    fallos = len(resultado.failures) + len(resultado.errors)
    return resultado.testsRun, fallos


def main():
    verbosidad = 2 if "-v" in sys.argv else 1

    total_func, fallos_func = _ejecutar_estilo_funciones()
    total_unit, fallos_unit = _ejecutar_estilo_unittest(verbosidad)

    total = (total_func or 0) + total_unit
    fallos = fallos_func + fallos_unit

    print("\n" + "=" * 74)
    print(" RESULTADO GLOBAL DE LA SUITE")
    print("-" * 74)
    if total_func is None:
        print(f"  Bloque 1 (funcional)  : NO EJECUTADO — error de importacion")
    else:
        print(f"  Bloque 1 (funcional)  : {total_func - fallos_func}/{total_func} OK")
    print(f"  Bloque 2 (unittest)   : {total_unit - fallos_unit}/{total_unit} OK")
    print("-" * 74)
    if fallos:
        print(f"  TOTAL: {total - fallos}/{total} casos OK — {fallos} FALLO(S)")
        print("=" * 74)
        return 1
    print(f"  TOTAL: {total}/{total} casos OK")
    print("=" * 74)
    return 0


if __name__ == "__main__":
    sys.exit(main())
