#!/bin/bash

# 1. 가상환경 생성 (선택사항)
# python3 -m venv venv
# source venv/bin/activate

apt-get update
apt-get upgrade
apt install openjdk-17-jdk openjdk-17-jre

# 2. requirements.txt 설치
if [ -f "requirements.txt" ]; then
    echo "[*] Installing Python dependencies from requirements.txt..."
    pip install -r requirements.txt
else
    echo "[!] requirements.txt not found!"
    exit 1
fi

# 3 LLM4Decompile Model Download
echo "[*] Downloading LLM4Binary/llm4decompile-22b-v2 from Hugging Face..."

python3 - <<EOF
from huggingface_hub import snapshot_download

snapshot_download(
    repo_id="LLM4Binary/llm4decompile-22b-v2",
    revision="main",
    local_dir="llm4decompile-22b-v2"
)
EOF

echo "[+] Download complete. Files are saved in ./llm4decompile-22b-v2"

# Ghidra Download 
wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0.3_build/ghidra_11.0.3_PUBLIC_20240410.zip
unzip ghidra_11.0.3_PUBLIC_20240410.zip


