#!/data/data/com.termux/files/usr/bin/bash
set -eu

if [ -z "${PREFIX:-}" ] || [ ! -d "$PREFIX/bin" ]; then
    echo "Este instalador foi feito para o Termux."
    exit 1
fi

DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

pkg install python -y
python -m pip install requests

install -m 755 "$DIR/gmap.py" "$PREFIX/bin/gmap"

echo "GMAP instalado com sucesso!"
echo "Site oficial: https://gmap-org.netlify.app/"
echo "Execute: gmap --help"
