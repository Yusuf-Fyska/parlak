# Surface & OWASP Signal Scanner (Single Node)

Python-based single-node scanner for surface discovery + OWASP signal generation. Control + Scan aynı proses, çıktılar direkt Elasticsearch’e bulk gider. Varsayılan SAFE_MODE=1 (ham paket, exploit, brute-force yok).

## Mimari (metin şema)

CLI → Policy (allowlist + rate/budget) → Pipeline (Pass-0/1/2) → Probers → ELK bulk writer → In-memory state (+opsiyonel JSON cache) → CLI report

## Bileşenler

- Scanner Engine: TCP/TLS/HTTP/Web probers (connect/HEAD/GET, güvenli).
- Policy Engine: allowlist, bütçe, concurrency, backoff.
- Pipeline Engine: Pass-0 (DNS/TLS/HEAD) → Pass-1 (L4 connect) → Pass-2 (OWASP sinyalleri).
- ELK Adapter: bulk ingest, basit query.
- State Manager: RAM + opsiyonel JSON cache (Postgres/Redis yok).

## Elasticsearch Indexleri

- `surface-assets`: discovery çıktısı.
- `surface-open-ports`: TCP connect + banner/TLS/HTTP sinyali.
- `surface-owasp-signals`: Pass-2 sinyal seti (header/cookie/CORS/default paths).
- `surface-web-findings`: korele bulgular.

Ortak alanlar: `timestamp, asset, ip, confidence`; `port/owasp_id` ilgili indexte dolu, gerekirse null. Mapping önerisi: `asset` keyword, `ip` ip, `port` integer, `timestamp` date, `headers` flattened.

## CLI / API

```bash
python -m cli.main verify                # config + ES bağlantı testi, allowlist doğrulama
python -m cli.main discover example.com  # Pass-0, ES: surface-assets
python -m cli.main scan example.com      # Pass-1 + Pass-2, ES: open-ports + signals + web-findings
python -m cli.main report example.com    # ES veya local state’den bulguları JSON yazdırır
```

`--write-test-doc` ile `verify` deneme dokümanı yazabilir.

API (FastAPI proxy, ES direkt açılmaz):
```bash
uvicorn api.server:app --host 0.0.0.0 --port 8000
# POST /api/discover {"target": "example.com"}
# POST /api/scan {"target": "example.com"}
# GET  /api/report?asset=example.com
# GET  /api/assets?query=ex
# GET  /api/health
```

## Proje Yapısı

- `core/`: config, modeller, in-memory state, authz/allowlist.
- `policy/`: policy engine, risk scoring.
- `pipeline/`: Pass-0/1/2 orchestrasyonu.
- `probers/`: tcp/tls/http/web probers (safe).
- `owasp/`: sinyal kuralları + evidence.
- `elk/`: Elasticsearch adapter.
- `cli/`: argparse tabanlı CLI.
- `config/`, `tests/`: örnekler ve test iskeleti.

## Çalıştırma (özet)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # ELASTICSEARCH_URL, ALLOWLIST_CIDRS/DOMAINS, SAFE_MODE=1 vb. doldur
python -m cli.main verify
python -m cli.main discover example.com
python -m cli.main scan example.com
python -m cli.main report example.com
```

## Politika Parametreleri (env)

- `ALLOWLIST_CIDRS`, `ALLOWLIST_DOMAINS` (zorunlu, yoksa tarama başlamaz)
- `GLOBAL_CONCURRENCY`, `PER_TARGET_CONCURRENCY`
- `SCAN_TIME_BUDGET_PER_TARGET`, `CAMPAIGN_TIME_BUDGET`
- `HTTP_TIMEOUTS`, `TLS_TIMEOUTS`
- `TOP_PORTS_WEB`, `TOP_PORTS_REMOTE`, `TOP_PORTS_DB`
- `SAFE_MODE`

## Ne Değil

- Exploit/pentest framework değil, brute-force yok.
- Queue/worker/DB yok; tek proses, tek sunucu.
