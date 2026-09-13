#!/bin/sh
# Libera ARP ativo e escuta passiva sem rodar o aplicativo inteiro como root.
#
# AppImage NÃO preserva capabilities: por isso os alvos de bundle são deb e
# rpm. Em AppImage o app funciona, mas só em modo limitado.
set -e
BIN=/usr/bin/SentinelStack
if command -v setcap >/dev/null 2>&1; then
    setcap cap_net_raw,cap_net_admin+eip "$BIN" || \
        echo "SentinelStack: setcap falhou. O aplicativo abre em modo limitado."
fi
