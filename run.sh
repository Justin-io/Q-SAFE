#!/bin/bash

# Setup
if [ -f .env ]; then export $(cat .env | xargs); fi
rm -f guardian guardian.o scan_list.txt suspicious_targets.txt

# Build
nasm -f elf64 guardian.asm -o guardian.o
gcc guardian.o -o guardian -no-pie

# Playground
cat <<EOF > innocent_script.py
print("Hello World")
EOF

cat <<EOF > rootkit_installer.sh
#!/bin/bash
# Suspicious name, likely to be picked by Triage
echo "Installing kernel module..."
rm -rf /var/log
EOF

cat <<EOF > payload.elf
# Fake ELF header
ELF...
malicious_code_here
EOF

echo "[*] Launching Q-SAFE v3 (Deep Agentic Flow)..."
./guardian
