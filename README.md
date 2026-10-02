# Zeek Botnet + Multi-Behavior Detector Installer v1.3.1

Installer ini memasang **Zeek + Random Forest botnet detector + multi-behavior detector + Filebeat khusus detector** tanpa menimpa Filebeat yang sudah ada.

## Fitur utama v1.3.1

### 1. Traffic Elasticsearch tidak lagi menjadi alert botnet

Endpoint Elasticsearch dari `--es-host` otomatis dimasukkan ke daftar known service yang diabaikan detector.

Default:

```text
https://10.70.128.26:9200
```

maka exact service berikut otomatis diabaikan:

```text
10.70.128.26:9200
```

Suppression berlaku jika endpoint tersebut muncul sebagai sisi originator **atau** responder di Zeek `conn.log`.

Traffic exact `10.70.128.26:9200`:

- tidak diinferensi oleh Random Forest,
- tidak ditulis ke `detections.jsonl`,
- tidak ditulis ke `botnet_alerts.jsonl`,
- tidak menghasilkan behavior alert seperti flood/beaconing.

**Hanya IP+port exact yang diabaikan.** Traffic lain dari/ke `10.70.128.26` pada port lain tetap diperiksa.

Tambahkan known service lain bila perlu:

```bash
sudo ./install.sh \
  --interface enp0s3 \
  --ignore-service 10.70.128.50:5432 \
  --ignore-service 10.70.128.60:6379
```

### 2. Enam behavior alert

```text
HTTP_BRUTE_FORCE
SSH_BRUTE_FORCE
PORT_SCAN
HOST_SCAN
CONNECTION_FLOOD
BEACONING
```

Semua behavior berjalan dalam **shadow mode**: hanya mendeteksi/logging, tidak melakukan block/drop.

Default rule:

| Alert | Rule default |
|---|---|
| `HTTP_BRUTE_FORCE` | 20 POST ke endpoint login dalam 60 detik |
| `SSH_BRUTE_FORCE` | 10 koneksi TCP ke port 22 dalam 60 detik |
| `PORT_SCAN` | 15 destination port unik pada host yang sama dalam 60 detik |
| `HOST_SCAN` | 15 destination host unik pada port yang sama dalam 60 detik |
| `CONNECTION_FLOOD` | 100 koneksi ke service yang sama dalam 10 detik |
| `BEACONING` | >=6 koneksi periodik, mean interval 5-300 detik, CV <=0.15, observasi 600 detik |

`SSH_BRUTE_FORCE`, `CONNECTION_FLOOD`, dan `BEACONING` adalah **behavioral heuristic** dari metadata koneksi Zeek; bukan bukti autentikasi gagal atau malware secara mandiri. Validasi threshold dengan traffic normal lingkungan Anda.

## Struktur bundle

```text
zeek-botnet-installer-v1.3.1/
├── install.sh
├── verify.sh
├── uninstall.sh
├── deploy-many.sh
├── hosts.example
├── README.md
├── CHANGELOG.md
└── payload/
    ├── models/
    │   ├── rf_official_bro_final_pipeline.joblib
    │   └── zeek_official_active_feature_config.pkl
    └── src/
        ├── feature_engineering.py
        ├── detector.py
        ├── behavior_detector.py
        └── monitor.sh
```

## Model wajib dimasukkan

Model final tidak disertakan dalam ZIP ini karena file model tidak tersedia pada bundle percakapan saat installer dibuat.

Copy dua file final ke:

```text
payload/models/rf_official_bro_final_pipeline.joblib
payload/models/zeek_official_active_feature_config.pkl
```

Installer memvalidasi kontrak:

```text
40 raw features -> 433 encoded features
```

## Install AlmaLinux / Rocky / RHEL / CentOS

```bash
unzip zeek-botnet-installer-v1.3.1.zip
cd zeek-botnet-installer-v1.3.1
chmod +x install.sh verify.sh uninstall.sh deploy-many.sh
ls -lh payload/models/
sudo ./install.sh --interface enp0s3
```

Jika Zeek sudah ada:

```bash
sudo ./install.sh --interface enp0s3 --skip-zeek-install
```

Tidak ada build/compile Zeek dari source.

## Install Ubuntu / Debian

```bash
unzip zeek-botnet-installer-v1.3.1.zip
cd zeek-botnet-installer-v1.3.1
chmod +x install.sh verify.sh uninstall.sh deploy-many.sh
sudo ./install.sh --interface enp0s3
```

## Elasticsearch / Filebeat

Default:

```text
ES URL : https://10.70.128.26:9200
User   : elastic
```

Password diminta secara tersembunyi atau dapat diberikan via root-only file:

```bash
sudo sh -c 'printf "%s\n" "PASSWORD_ELASTIC" > /root/es.pass'
sudo chmod 600 /root/es.pass
sudo ./install.sh \
  --interface enp0s3 \
  --es-password-file /root/es.pass
```

Filebeat existing tidak diubah:

```text
/etc/filebeat/filebeat.yml     TIDAK DIUBAH
filebeat.service               TIDAK DIUBAH/RESTART
```

Instance detector terpisah:

```text
/etc/filebeat-botnet/filebeat.yml
/etc/filebeat-botnet/filebeat.keystore
filebeat-botnet.service
/var/lib/filebeat-botnet
/var/log/filebeat-botnet
```

Index:

```text
capstone-zeek-botnet-alerts-YYYY.MM.DD
capstone-zeek-behavior-alerts-YYYY.MM.DD
```

Jika menggunakan `--ship-all-predictions`:

```text
capstone-zeek-botnet-predictions-YYYY.MM.DD
```

Data View Kibana gabungan dengan Filebeat lama:

```text
filebeat-*,capstone-zeek-*
```

Timestamp:

```text
@timestamp
```

## Output lokal

```text
/opt/zeek-botnet-detector/logs/detections.jsonl
/opt/zeek-botnet-detector/logs/botnet_alerts.jsonl
/opt/zeek-botnet-detector/logs/behavior_alerts.jsonl
```

Known service yang di-ignore tidak masuk ke tiga file di atas.

## Opsi behavior

```text
--behavior-window SEC
--http-threshold N
--ssh-threshold N
--port-threshold N
--host-threshold N
--flood-window SEC
--flood-threshold N
--beacon-window SEC
--beacon-min-connections N
--beacon-min-interval SEC
--beacon-max-interval SEC
--beacon-max-cv FLOAT
--behavior-cooldown SEC
--ignore-service HOST:PORT
```

Contoh custom:

```bash
sudo ./install.sh \
  --interface enp0s3 \
  --http-threshold 20 \
  --ssh-threshold 10 \
  --port-threshold 15 \
  --host-threshold 15 \
  --flood-window 10 \
  --flood-threshold 100 \
  --beacon-window 600 \
  --beacon-min-connections 6 \
  --beacon-max-cv 0.15
```

## Zeek path dan SELinux

Installer membaca `logdir`/`spooldir` dari:

```bash
zeekctl config
```

Sehingga AlmaLinux EPEL seperti berikut otomatis didukung:

```text
logdir=/var/log/zeek/logs
spooldir=/var/log/zeek/spool
conn.log=/var/log/zeek/logs/current/conn.log
http.log=/var/log/zeek/logs/current/http.log
```

Pada SELinux enforcing, runtime Python `uv` diberi context executable secara terbatas pada:

```text
/var/lib/zeekbot/.local/share/uv/python
```

SELinux tidak dimatikan.

## Service

```bash
sudo systemctl status zeek-botnet-detector.service --no-pager
sudo systemctl status zeek-behavior-detector.service --no-pager
sudo systemctl status filebeat-botnet.service --no-pager
```

Cek command/service dan suppression:

```bash
sudo systemctl cat zeek-botnet-detector.service
sudo systemctl cat zeek-behavior-detector.service
cat /etc/zeek-botnet-detector.conf
```

Default harus memperlihatkan:

```text
--ignore-service 10.70.128.26:9200
```

## Verifikasi

```bash
sudo ./verify.sh
```

Monitor real-time:

```bash
/opt/zeek-botnet-detector/src/monitor.sh
```

## Upgrade dari v1.2.1

Masukkan model ke bundle v1.3.1, lalu jalankan installer baru. Installer menghentikan/mengganti hanya service miliknya sendiri dan membuat backup timestamp terhadap file yang diubah.

Existing Zeek package/config dan default Filebeat tidak dihapus.

## Uninstall detector

```bash
sudo ./uninstall.sh
```

Uninstall hanya menghapus detector + dedicated Filebeat instance. Default Filebeat dan paket/config Zeek tidak dihapus.


## v1.3.1 dedicated Filebeat keystore fix

This release explicitly stores the Elasticsearch password in:

```text
/etc/filebeat-botnet/filebeat.keystore
```

and pins that path in the dedicated Filebeat config and systemd unit. This avoids the package-default `/var/lib/filebeat/filebeat.keystore` being selected on some Ubuntu/Debian installations. The existing default Filebeat keystore is not copied, replaced, or deleted.

After installation, verify with:

```bash
sudo ./verify.sh
sudo systemctl status filebeat-botnet.service --no-pager -l
```
