#!/bin/bash
#
wget https://github.com/mitre-attack/attack-stix-data/raw/master/enterprise-attack/enterprise-attack.json
curl -fsSL https://ollama.com/install.sh | sh
ollama pull chih/llama-2-chat-attack
pip install -r requirements.txt
