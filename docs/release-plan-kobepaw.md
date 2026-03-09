# goop-veil Release Plan — kobepaw

## Overview

Release goop-veil under `kobepaw/goop-veil` (public) to protect original author privacy.
Target launch: Tuesday or Wednesday, March 10-11, 2026.

---

## Pre-Release Checklist

### 1. Identity Setup (Kobe, ~20 min)

```bash
# Create kobepaw GitHub account if not done
# Generate PAT with repo scope
# Use privacy-oriented email (e.g., kobepaw@protonmail.com or noreply)

# Auth gh CLI as kobepaw
gh auth login --hostname github.com  # authenticate as kobepaw

# Create public repo
gh repo create kobepaw/goop-veil --public \
  --description "WiFi privacy defense. Detect, mitigate, and document WiFi CSI surveillance."
```

### 2. Clean Export (Kobe, ~15 min)

**Approach: fresh git init (cleanest — no git history carries over)**

```bash
mkdir -p ~/code/kobepaw-release && cd ~/code/kobepaw-release

# Copy source from DGX Spark
scp -r infa@spark-c231:/home/infa/code/goop-veil/ ./goop-veil-source/

# Init clean repo
mkdir goop-veil && cd goop-veil
git init
git config user.name "kobepaw"
git config user.email "kobepaw@users.noreply.github.com"

# Copy files (exclude build artifacts)
rsync -av --exclude='.git' --exclude='.venv' --exclude='target' \
  --exclude='__pycache__' --exclude='*.so' --exclude='*.pyc' \
  --exclude='*.egg-info' --exclude='Cargo.lock' \
  ../goop-veil-source/ ./
```

### 3. Code Scrubbing (before first commit)

```bash
# Replace all brianwtaylor references
sed -i '' 's|kobepaw/goop-veil|kobepaw/goop-veil|g' README.md
sed -i '' 's|kobepaw/goop-veil|kobepaw/goop-veil|g' pyproject.toml

# Verify clean
grep -r "brianwtaylor\|brian.taylor818\|Brian Taylor" . \
  --include='*.py' --include='*.toml' --include='*.yml' \
  --include='*.md' --include='*.rs' --include='*.json'
# Expected: no output
```

### 4. Commit & Push

```bash
git remote add origin https://github.com/kobepaw/goop-veil.git
git add -A
git commit -m "Initial release: WiFi privacy defense system

Detection, mitigation, and legal evidence generation for WiFi CSI surveillance.
569 tests. Apache-2.0 licensed."

git push -u origin master
```

### 5. Build & Test on Kobe

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install maturin
maturin develop --features extension-module
pip install ".[dev]"
cargo test
pytest tests/ -v --tb=short
```

### 6. Tag Release

```bash
git tag -a v0.1.0 -m "v0.1.0: Initial public release"
git push origin v0.1.0
# GitHub Actions builds wheels for linux x86_64/aarch64, macOS x86_64/arm64
```

### 7. GitHub Presence

```bash
gh repo edit kobepaw/goop-veil \
  --add-topic wifi-security --add-topic privacy \
  --add-topic wifi-sensing --add-topic csi \
  --add-topic surveillance-defense --add-topic 802-11bf \
  --add-topic wifi-privacy --add-topic python --add-topic rust
```

Enable Discussions: Settings > Features > Discussions

---

## Launch Day Timeline (Tuesday/Wednesday)

| Time (ET) | Action |
|-----------|--------|
| 7:00 AM | Publish blog post |
| 8:00 AM | Verify GitHub release, wheels attached |
| 8:30 AM | Post Twitter/X thread (7 tweets) |
| 9:00 AM | Submit Hacker News "Show HN" |
| 9:05 AM | Post HN self-comment with technical details |
| 9:30 AM | Post r/privacy |
| 10:00 AM | Post r/netsec |
| 10:30 AM | Post r/homelab, r/selfhosted |
| 11:00 AM | Post Privacy Guides forum |
| 12:00 PM | Send EFF, ACLU, researcher emails |
| 12:00 PM | Submit PR to MCP servers list |
| All day | Monitor and respond to engagement |

---

## Identity Protection Rules

- NEVER push to kobepaw repo from a machine with brianwtaylor git config
- Use HTTPS + PAT (not SSH keys) for all kobepaw operations
- Never comment on kobepaw/goop-veil from brianwtaylor account
- Consider VPN for initial push if IP separation matters
- The fresh git init approach leaves zero forensic trail to original author

---

## Risk Mitigations

| Risk | Mitigation |
|------|-----------|
| Wheel build fails on GitHub Actions | Build manually on Spark + Kobe, upload via `gh release upload` |
| Identity linkage | Separate machines, browsers, VPN. Fresh git init. |
| HN flagged as self-promotion | "Show HN" is for launches. Include technical substance. |
| PyPI name squatted | Reserve immediately if concerned (minimal upload) |
| "Security theater" criticism | Lead with peer-reviewed effectiveness numbers |
