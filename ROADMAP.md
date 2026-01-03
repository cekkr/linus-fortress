# Roadmap

Security posture: assume capable attackers and prioritize least privilege, auditability, and safe rollback paths.

## Path 1: Core auth and storage modularization (short term)
- Extract auth/token utilities into `py/fortress/auth.py`.
- Extract storage helpers into `py/fortress/storage.py`.
- Keep `py/server.py` focused on route wiring and orchestration.

## Path 2: Monitoring baseline and anomaly detection (short term)
- Persist historical resource snapshots for hosts and containers.
- Compare new samples against baselines to flag rate-based anomalies (CPU deltas, network spikes).

## Path 3: Audit and scope enforcement tests (short term)
- Add unit tests for container scope enforcement rules.
- Add unit tests for audit logging behavior (mock LXC subprocess calls).

## Path 4: Integration tests and permission matrix (mid term)
- Add integration tests for core API flows.
- Validate the permission matrix across endpoints and scopes.

## Path 5: Recipes lifecycle management (mid term)
- Add export/import bundles for recipes.
- Track semantic versions and change history for recipe updates.
