# Changelog

## v1.3.1

- Fixes dedicated Filebeat authentication under systemd when `ES_PASSWORD` was accidentally written to the default `/var/lib/filebeat/filebeat.keystore`.
- Adds an explicit dedicated keystore at `/etc/filebeat-botnet/filebeat.keystore`.
- Pins `keystore.path` in both `filebeat.yml` and `filebeat-botnet.service`, so manual tests and systemd resolve the same secret store.
- Installer now verifies that the dedicated keystore exists and contains `ES_PASSWORD` before enabling the service.
- Installer now fails with recent journal output if `filebeat-botnet.service` cannot stay active after installation.
- `verify.sh` now checks the dedicated keystore and the systemd keystore-path override.
- Keeps the default Filebeat config, service, data registry, and default keystore untouched.

## v1.3.0

- Elasticsearch endpoint from `--es-host` is automatically excluded from ML inference and all detector alert logs by exact `IP:PORT` match.
- Added repeatable `--ignore-service HOST:PORT` for additional known internal services.
- Known-service suppression is also applied to behavior detection, preventing Filebeat/Elasticsearch traffic from creating flood/beacon false positives.
- Behavior detector expanded to six alert types:
  - `HTTP_BRUTE_FORCE`
  - `SSH_BRUTE_FORCE`
  - `PORT_SCAN`
  - `HOST_SCAN`
  - `CONNECTION_FLOOD`
  - `BEACONING`
- Added independent thresholds/windows for SSH brute force, host scan, flood, and beaconing.
- Monitor updated to display metrics from all six behavior alert types.
- Verification checks known-service suppression and all six behavior types.
- Retains v1.2.1 fixes: Zeek log path auto-detection, SELinux-safe uv Python runtime, package-only Zeek install, and isolated Filebeat instance.

## v1.2.1

- Detect Zeek live log root from `zeekctl config` instead of hardcoding `/var/log/zeek/current`.
- Fix SELinux `203/EXEC` for uv-managed Python on Alma/RHEL-family systems.
- Run uv from `/var/lib/zeekbot` so installers under private home directories do not trigger `uv.toml: Permission denied`.
