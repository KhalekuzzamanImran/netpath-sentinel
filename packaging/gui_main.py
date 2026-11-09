import sys

from netpath_sentinel.cli import main as cli_main
from netpath_sentinel.presentation.desktop.app import run

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--cli":
        del sys.argv[1]
        cli_main()
    else:
        raise SystemExit(run())
