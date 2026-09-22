import sys
import pathlib

# Make `app` importable when pytest is run from the backend/ directory.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
