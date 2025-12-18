# Single Node Surface Scanner Kurulum Rehberi (ELK Doğrudan Yazım)

Tüm bileşenler tek sunucuda, Postgres/Redis olmadan, çıktılar doğrudan Elasticsearch’e bulk yazılır. SAFE_MODE=1 varsayılan (ham paket yok, exploit yok, brute-force yok). Allowlist dolu değilse tarama başlamaz.

---

## OS hazırlığı (Ubuntu 22.04/24.04)
**Amaç:** Temiz temel sistem.  
**Ne Kuruyorum:** Güncellemeler, saat.  
**Komutlar:**
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y tzdata
timedatectl status
```
**Doğrulama:** `synchronized: yes`.  
**Hata olursa:** `sudo systemctl restart systemd-timesyncd`.

---

## Paketler
**Amaç:** Python, build araçları, git, SSL/HTTP araçları.  
**Ne Kuruyorum:** python3, venv, pip, git, build-essential, curl, openssl.  
**Komutlar:**
```bash
sudo apt install -y python3 python3-venv python3-pip git build-essential curl openssl
```
**Doğrulama:** `python3 --version`, `git --version`, `openssl version`.  
**Hata olursa:** `sudo apt update` ve tekrar deneyin.

---

## Repo klonlama
**Amaç:** Kaynak kodu almak.  
**Ne Kuruyorum:** `surface-scanner` dizini.  
**Komutlar:**
```bash
git clone PLACEHOLDER_REPO_URL surface-scanner
cd surface-scanner
```
**Doğrulama:** `ls` içinde `requirements.txt`, `cli/`, `pipeline/` görünmeli.  
**Hata olursa:** Repo URL/erişim anahtarını kontrol et.

---

## venv + requirements
**Amaç:** İzole Python ortamı ve bağımlılıklar.  
**Ne Kuruyorum:** `.venv`, pip paketleri.  
**Komutlar:**
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```
**Doğrulama:** `python -c "import elasticsearch; print('ok')"` → `ok`.  
**Hata olursa:** Proxy/SSL engeli varsa `pip install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt`.

---

## .env oluşturma
**Amaç:** ELK + policy ayarları (allowlist zorunlu).  
**Ne Kuruyorum:** `.env` dosyası.  
**Komutlar:**
```bash
cat > .env <<'EOF'
ELASTICSEARCH_URL=PLACEHOLDER_ELASTICSEARCH_URL
ELASTICSEARCH_USER=PLACEHOLDER_USER
ELASTICSEARCH_PASS=PLACEHOLDER_PASS
# veya ELASTICSEARCH_API_KEY=PLACEHOLDER_KEY
ELASTICSEARCH_VERIFY_CERTS=1
ELASTICSEARCH_CA_CERT=PLACEHOLDER_CA_PATH  # yoksa boş bırak
SAFE_MODE=1
ALLOWLIST_CIDRS=PLACEHOLDER_CIDRS   # örn: 203.0.113.0/24,198.51.100.10/32
ALLOWLIST_DOMAINS=PLACEHOLDER_DOMAINS  # örn: example.com,example.org
TOP_PORTS_WEB=80,443,8080,8443,8000,3000,5000
GLOBAL_CONCURRENCY=32
PER_TARGET_CONCURRENCY=4
SCAN_TIME_BUDGET_PER_TARGET=120
VERIFY_WRITE_TEST_DOC=0
JSON_CACHE_PATH=state-cache.json   # opsiyonel, istemezsen boş bırak
EOF
```
**Doğrulama:** `grep ALLOWLIST .env` dolu; `python -m cli.main verify`.  
**Hata olursa:** ELASTICSEARCH_URL/cred veya allowlist formatını düzelt.

---

## Elasticsearch bağlantı testi
**Amaç:** ELK erişimini doğrulamak.  
**Ne Kuruyorum:** Test erişim.  
**Komutlar:**
```bash
curl -u PLACEHOLDER_USER:PLACEHOLDER_PASS https://ELK_HOSTNAME:9200
python -m cli.main verify
```
`--write-test-doc` istersen: `python -m cli.main verify --write-test-doc`  
**Doğrulama:** curl 200 JSON; verify sonucu `elk: true`.  
**Hata olursa:** Firewall/SSL/credential/CA yolu kontrol et.

---

## Index template (Kibana Dev Tools)
**Amaç:** surface-* indexleri için mapping.  
**Ne Kuruyorum:** Index template.  
**Komutlar (Kibana Dev Tools):**
```json
PUT _index_template/surface-scanner-template
{
  "index_patterns": ["surface-*"],
  "template": {
    "mappings": {
      "dynamic": "true",
      "properties": {
        "asset": { "type": "keyword" },
        "ip": { "type": "ip" },
        "port": { "type": "integer" },
        "timestamp": { "type": "date" },
        "owasp_id": { "type": "keyword" },
        "confidence": { "type": "integer" },
        "headers": { "type": "flattened" }
      }
    }
  }
}
```
**Doğrulama:** `GET _index_template/surface-scanner-template`.  
**Hata olursa:** Yetki/syntax düzelt.

---

## İlk tarama
**Amaç:** Uçtan uca discovery + scan.  
**Ne Kuruyorum:** Pass-0/1/2 çalıştırma.  
**Komutlar:**
```bash
python -m cli.main discover example.com
python -m cli.main scan example.com
```
**Doğrulama:** CLI çıktısında “surface-*” bulk işlemleri hatasız.  
**Hata olursa:** Allowlist’e hedefi ekle; ES bağlantısını yeniden test et.

---

## ELK’de doğrulama sorguları (Kibana)
- `surface-assets`:
```json
GET surface-assets/_search
{ "query": { "term": { "asset.keyword": "example.com" } }, "size": 5 }
```
- `surface-open-ports`:
```json
GET surface-open-ports/_search
{ "query": { "term": { "asset.keyword": "example.com" } }, "size": 5 }
```
- `surface-owasp-signals`:
```json
GET surface-owasp-signals/_search
{ "query": { "term": { "asset.keyword": "example.com" } }, "size": 5 }
```
- `surface-web-findings`:
```json
GET surface-web-findings/_search
{ "query": { "term": { "asset.keyword": "example.com" } }, "size": 5 }
```
**Doğrulama:** hits > 0; timestamp/asset/ip/port/confidence dolu.  
**Hata olursa:** index adı/auth/CA ayarlarını kontrol et.

---

## CLI hızlı referans
```bash
python -m cli.main verify                # config + ES connectivity (yazmaz, --write-test-doc ile yazar)
python -m cli.main discover <asset>      # Pass-0, surface-assets
python -m cli.main scan <asset>          # Pass-1 + Pass-2, open-ports + signals + web-findings
python -m cli.main report <asset>        # ES veya local state’ten bulguları JSON
```

---

## Final Checklist
- [ ] `.env` dolu, SAFE_MODE=1, ALLOWLIST_* set.
- [ ] `python -m cli.main verify` → `allowlist: true`, `elk: true`.
- [ ] Kibana template yüklendi (`surface-scanner-template`).
- [ ] `discover` ve `scan` çalıştı, surface-* indexlerinde veri var.
- [ ] `report <asset>` JSON döndürüyor.
- [ ] (Opsiyonel) `JSON_CACHE_PATH` ile lokal cache yazılıyor.
