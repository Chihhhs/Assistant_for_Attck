#!/bin/bash
#
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama2
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
