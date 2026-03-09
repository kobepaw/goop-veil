# goop-veil Release Instructions for Kobe

## Priority 1: Fix Codex Auth (run in Terminal on Kobe)

```bash
cd ~/code/goop-veil
./reauth-codex.sh
```

This will open a device code flow — follow the prompts in the browser.

## Priority 2: Release goop-veil under kobepaw

### 2a. Create the repo
```bash
gh auth login  # authenticate as kobepaw
gh repo create kobepaw/goop-veil --public \
  --description "WiFi privacy defense. Detect, mitigate, and document WiFi CSI surveillance."
```

### 2b. Scrub identity and push
```bash
cd ~/code/goop-veil
sed -i "" "s|kobepaw/goop-veil|kobepaw/goop-veil|g" README.md
sed -i "" "s|kobepaw/goop-veil|kobepaw/goop-veil|g" pyproject.toml

# Verify clean
grep -r "brianwtaylor" . --include="*.py" --include="*.toml" --include="*.yml" --include="*.md"
# Should return nothing

# Init fresh repo
cd ..
mv goop-veil goop-veil-source
mkdir goop-veil && cd goop-veil
git init
git config user.name "kobepaw"
git config user.email "kobepaw@users.noreply.github.com"

rsync -av --exclude=".git" --exclude=".venv" --exclude="target" \
  --exclude="__pycache__" --exclude="*.so" --exclude="*.pyc" \
  --exclude="*.egg-info" --exclude="Cargo.lock" \
  ../goop-veil-source/ ./

git add -A
git commit -m "Initial release: WiFi privacy defense system

Detection, mitigation, and legal evidence generation for WiFi CSI surveillance.
569 tests. Apache-2.0 licensed."

git remote add origin https://github.com/kobepaw/goop-veil.git
git push -u origin master
```

### 2c. Build and test
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install maturin
maturin develop --features extension-module
pip install ".[dev]"
cargo test
pytest tests/ -v --tb=short
```

### 2d. Tag and release
```bash
git tag -a v0.1.0 -m "v0.1.0: Initial public release"
git push origin v0.1.0
# GitHub Actions will build wheels automatically
```

### 2e. GitHub topics
```bash
gh repo edit kobepaw/goop-veil \
  --add-topic wifi-security --add-topic privacy \
  --add-topic wifi-sensing --add-topic surveillance-defense \
  --add-topic wifi-privacy --add-topic python --add-topic rust
```

## Marketing Materials

All ready in `docs/launch-materials.md`:
- Twitter/X thread (7 tweets)
- Hacker News submission
- Reddit posts (r/privacy, r/netsec, r/selfhosted)
- Blog post (~1900 words)
- Privacy Guides forum post
- GitHub release notes

## Timeline

Target: Tuesday March 10 or Wednesday March 11.
The WiFi surveillance story is viral NOW — every day matters.
