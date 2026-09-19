# Internal service certificate renewal

Compose controller and relay certificates last 30 days. These are separate from
the relay's automatically managed public HTTPS certificate. On a systemd host
with Python 3, OpenSSL and Docker Compose, install the daily renewal job:

```sh
sudo install -m 755 deploy/compose/renew-service-certificates.py /opt/laneway/
sudo install -m 644 deploy/compose/laneway-certificate-renewal.service /etc/systemd/system/
sudo install -m 644 deploy/compose/laneway-certificate-renewal.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now laneway-certificate-renewal.timer
sudo systemctl start laneway-certificate-renewal.service
```

The script uses `/opt/laneway/compose.yaml`, its `.env`, and the digest-pinned
administrator image. It checks daily and after boot, renewing both services when
either has seven days or less remaining. It preserves network/service IDs and
DNS/IP names, verifies the chain and private-key match, and retains root-only
backups in `generated/backups/certificate-renewal`. The CA is not replaced.

Renewal recreates both containers, briefly interrupting connections. If health
checks fail, the prior certificates are restored and containers recreated again.
Avoid running upgrades concurrently. The renewal job locks against another copy
of itself, but does not coordinate with the deployment upgrader. Keep backups
protected: they contain private keys. Review their retention periodically.

```sh
sudo python3 /opt/laneway/renew-service-certificates.py --check
sudo systemctl list-timers laneway-certificate-renewal.timer
sudo journalctl -u laneway-certificate-renewal.service
# Exercise issuance and restart immediately, even when certificates are fresh:
sudo python3 /opt/laneway/renew-service-certificates.py --force
```

Failures appear in the systemd service status/journal and are retried at the next
scheduled check. No external notification delivery is configured by these units.
The root/intermediate must remain valid for at least 37 days; nearing that limit
fails the job for operator attention rather than silently rotating trust anchors.
Node/client identity renewal is a separate lifecycle and is not handled here.

For a different deployment directory, override the unit's `ExecStart` and pass
`--directory /absolute/deployment/path`. Run the regression tests with:

```sh
python3 -m unittest discover -s deploy/compose -p test_service_certificate_renewal.py
```
