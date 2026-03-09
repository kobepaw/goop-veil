#\!/bin/bash
set -e
echo "=== Step 1: Re-authenticate Codex CLI ==="
codex login --device-auth

echo ""
echo "=== Step 2: Re-authenticate OpenClaw ==="
openclaw models auth login --provider openai-codex --set-default

echo ""
echo "=== Step 3: Restart gateway ==="
kill $(pgrep -f "openclaw-gateway") 2>/dev/null
kill $(pgrep -f "openclaw$" | head -1) 2>/dev/null
sleep 2
nohup openclaw gateway > /tmp/openclaw.log 2>&1 &
sleep 3

echo ""
echo "=== Step 4: Verify ==="
openclaw agents list | grep Model
echo ""
echo "=== Done\! Send a test message via Signal. ==="
