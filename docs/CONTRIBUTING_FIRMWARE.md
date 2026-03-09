# Experimental Firmware Contribution Notes

The firmware-related components in this repository are currently **experimental** and are **not** part of the initial supported public release surface.

That is intentional.

We would rather be honest about firmware maturity than overclaim readiness.

## Good contribution areas
- TX pipeline completion and validation
- station lifecycle wiring / association table handling
- authenticated command channel design
- audit-signing implementation and verification
- hardware validation across real ESP32 setups
- documentation for provisioning, rollback, and safety testing

## Expectations
- safety first
- conservative defaults
- clear documentation of assumptions and limits
- reproducible testing notes
- no overclaiming around compliance or outcome claims

## Public posture
If you contribute to firmware, assume your work will be reviewed under a stricter standard than experimental internal code. The public-facing project needs truthful scope boundaries and defensible safety claims.

## Recommended contributor mindset
Help make the firmware path real, measurable, and safe enough to graduate into a supported surface later.
