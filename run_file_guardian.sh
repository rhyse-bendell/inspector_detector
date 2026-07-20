#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"

if [ ! -x ".venv/bin/python" ]; then
    python3 -m venv .venv
fi

.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt || {
    printf '%s\n' "Dependency installation failed; starting with reduced capability." >&2
}
.venv/bin/python app.py
