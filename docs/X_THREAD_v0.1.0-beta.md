# X Thread — goop-veil v0.1.0-beta

## Post 1
WiFi sensing is real, but a lot of the internet is mixing lab demos with product reality.

We built **goop-veil**, an open-source **software-only research preview** for detecting potential WiFi sensing activity, applying guarded mitigations through supported routers, and generating documentation artifacts for review.

## Post 2
This is about RF sensing, not reading your internet traffic.

Researchers have shown that ordinary WiFi signals can reveal presence, motion, breathing, and heartbeat under some conditions — including through walls.

## Post 3
Our goal with goop-veil is simple:
- **detect** suspicious signals
- **degrade** sensing reliability where possible
- **document** what you’re seeing

Not panic. Not hype. Practical defense tooling.

## Post 4
What’s in the beta:
- scan / detect workflows
- guarded router-based mitigation paths
- documentation / evidence bundle generation
- Linux-first support for scanning/capture flows

## Post 5
Important caveat: this is a **research preview**.

Detection is heuristic.
Mitigation effectiveness varies.
The project does **not** provide compliance certification or guaranteed outcomes.

## Post 6
We also kept firmware out of the initial supported release surface.

That path is still experimental, and we’d rather be honest about scope than overclaim readiness.

## Post 7
If you want to kick the tires, review the repo and docs here:
https://github.com/kobepaw/goop-veil

If you test it, we want:
- router compatibility reports
- false positives / negatives
- install issues
- contributors for the experimental firmware path
