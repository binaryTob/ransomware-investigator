"""Verify the handoff archive; never extract or execute its contents."""
import argparse
import json
from pathlib import Path
import sys

# This file also serves as VERIFICAR.py at the root of an extracted handoff.
here = Path(__file__).resolve().parent
sys.path.insert(0, str(here / 'proyecto' if (here / 'proyecto').is_dir() else here.parent))
from tools.handoff_bundle import verify_bundle


def main():
    parser = argparse.ArgumentParser(description='Verificar hashes de entrega sin extraer ni ejecutar evidencia.')
    parser.add_argument('zip', type=Path)
    args = parser.parse_args()
    try:
        result = verify_bundle(args.zip)
    except Exception as exc:
        print(json.dumps({'valid': False, 'error_type': type(exc).__name__, 'content_not_executed': True}))
        return 2
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
