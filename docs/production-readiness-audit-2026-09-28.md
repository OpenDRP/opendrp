# Комплексный аудит production readiness — OpenDRP 0.1.1

**Дата:** 2026-09-28 · **Ревизия:** `main` @ `c41fb3d` (релиз `v0.1.1`) · **Объём:** архитектура, коннекторы, развёртывание, кибербезопасность, фреймворки и зависимости

---

## 0. Резюме и вердикт

**Вердикт: платформа пригодна к production-эксплуатации в сегменте small/medium self-hosted развёртываний (одноузловая Compose-инсталляция за TLS-терминатором), с перечисленными ниже рисками, ни один из которых не является немедленным блокером.**

Сильные стороны — редкий для проекта такого размера уровень проработки безопасности (цепочка аудита с HMAC, пер-коннекторные токены с хранением дайджеста, SSRF-guard, ротация секретов, MFA с onboarding-гейтами), честная инженерная дисциплина (пины зависимостей, запатированные по SHA действия CI, гейты на дрейф схемы и конфигурации) и хорошо документированная эксплуатация.

Главные зоны роста: **рассинхронизированные манифесты зависимостей** (из-за чего Dependabot отчитывается о3 HIGH-уязвимостях рантайм-пакета, которого в образе может не быть, и наоборот — реальные пины не проверяются),21 открытая security alert, статус CodeQL (v3 устареет к декабрю 2026), отсутствие HA-сценария и единственная точка планировщика.

---

## 1. Архитектура

### 1.1 Общая форма: core + connectors

Ядро (FastAPI) владеет всем состоянием и всей бизнес-логикой: активы, авторизация, валидация, джобы, ingestion, дедупликация, алерты, расписание, аудит, REST API. Внешние источники данных работают в независимых коннектор-контейнерах и общаются с ядром только по HTTP-протоколу (pull-модель, вдохновлённая OpenCTI import connectors).

```
Browser → frontend (Nginx + React SPA) → /api/ → backend (FastAPI)
                                                   ├─ PostgreSQL 17 (SQLAlchemy async + asyncpg pool)
                                                   ├─ Redis 7 (Celery broker + дедуп расписаний + rate limit)
                                                   ├─ celery-worker (отчёты, доставка алертов, retention)
                                                   └─ celery-beat (минутный планировщик сканов)

connector-dnstwist / connector-shodan / connector-hibp → core connector API
```

Ключевое архитектурное свойство: **коннекторы stateless и не имеют доступа к БД** — все записи выполняет ядро. Платформа не знает список «своих» коннекторов: модули и типы джоб объявляются самими коннекторами (self-declared manifest), а операторские модули пишут находки в универсальное JSON-хранилище `drp_findings` без изменения ядра, миграций или фронтенда. Это соответствует требованию AGENTS.md об унифицированных интерфейсах core/plugins.

**Оценка архитектуры: сильная.** Чёткое разделение ответственности, stateless-ядро (горизонтальное масштабирование API возможно), «модули — данные, а не код».

### 1.2 Backend-слой

| Слой | Содержимое |
|---|---|
| `app/api/v1/routers/` | 12 роутеров (~4,6 тыс. строк): auth (1166 строк — самый сложный: сессии, MFA, onboarding), connectors (762), users, audit, breaches, phishing, reports, settings, modules, jobs, dashboard, alerts |
| `app/services/` | доменные сервисы: ingestion, connector_manifest/credentials/service, alert_delivery, job_service, module_registry, scan_admission, report_service, settings_service, phishing/whois |
| `app/core/` | security (PyJWT + bcrypt), crypto (MultiFernet), audit + audit_chain (HMAC-цепочка), rate limiting (3 контура), outbound (SSRF-guard), artifact_path, database (пул + таймауты), totp, celery_app |
| `app/tasks/` | Celery-задачи: alert_tasks, report_tasks, retention_tasks, scheduler_tasks, integrity_tasks |
| `app/models/` | 13 моделей; миграций — одна (`0001_initial_schema`, сшитый baseline), схем-гейты проверяют граф и расхождение ORM↔схема |

Интересные решения: `statement_timeout=30s` / `lock_timeout=5s` / `idle_in_transaction_session_timeout=60s` на соединение (медленный запрос не валит платформу — возвращает `503 database_busy` с `Retry-After`); миграции при старте под PostgreSQL advisory lock (два реплики-API не конкурируют); пул `DB_POOL_SIZE=20 + MAX_OVERFLOW=10`, LIFO, recycle 30 мин.

### 1.3 Frontend

React 18.3 SPA + Vite 5 + TypeScript 5.6 + Tailwind 4 (beta) + Radix UI + zustand + TanStack Query + react-hook-form/zod. 13 страниц (Dashboard, Assets, Phishing, Breaches, Modules, Reports, Users, Audit, Settings, Login, Onboarding, Security, NotFound). Nginx отдаёт статику и проксирует `/api/`; `index.html` — `Cache-Control: no-cache` (защита от «устаревшей оболочки»).

Продуманные фронтенд-решения: собственный gate на циклические импорты в Vite-сборке (после реального инцидента с потерей сессии при F5 из-за цикла `store/auth.ts ↔ lib/api.ts`), single-flight refresh, «мост» `session-bridge.ts` без импортов.

**Слабое место (задокументировано самим проектом):** API-клиент рукописный, пути эндпоинтов — строковые литералы; удаление роута на бэке не ломает сборку. Генерация клиента из OpenAPI закрыла бы целый класс дефектов.

---

## 2. Система коннекторов

### 2.1 Протокол и SDK

Общий SDK `connectors/base/opendrp_connector` (643 строки `base.py` + сетевые утилиты) реализует цикл: `register → poll work (атомарный claim одной джобы, 204 при пустой очереди) → run_scan → submit findings батчами → complete/report_failure`. Плюс heartbeat, liveness-файл для HEALTHCHECK, бэкофф при недоступности ядра, structlog JSON с `X-Request-ID`.

**Self-declared manifest** — ключевая фича: коннектор объявляет `CONNECTOR_TYPE` (модуль), `CONNECTOR_JOB_TYPE` (уникальный тип джобы — гарантия изоляции работы), `CONNECTOR_FINDING_KIND`, `CONNECTOR_ASSET_TYPES`, `CONNECTOR_CONFIG_SCHEMA`. Ядро валидирует сабмишены по схеме, рендерит форму настроек в UI и показывает коннектор в истории джоб — **без изменения фронтенда и ядра**.

### 2.2 First-party коннекторы

| Коннектор | Модуль | Строк кода | Источник | Особенности |
|---|---|---|---|---|
| dnstwist | phishing | 289 | dnstwist-бинарь + DNS | ограниченный набор фаззеров по умолчанию, дорогое — opt-in |
| shodan | phishing | 508 | Shodan API | 3 переключаемые capability, пошаговый `capability_results` в summary, честный «partial scan» при отказе провайдера, retry только транзиентных ошибок с `Retry-After` |
| hibp | breaches | 298 | HIBP API | email/domain lookup, документированный integration key для smoke-проверки |

### 2.3 Контракт данных

Схемы находок провайдеронейтральны (`phishing:*` — `phishing_domain`+`matched_asset`; `breaches:*` — `breach_name`+`matched_email/matched_domain`), вендорские поля уходят в `attributes` (≤32 ключей, lowercase-идентификаторы, контрол-символы отвергаются, значения хранятся дословно). Дедуп на стороне ядра: уникальность phishing-домена и пары (breach, matched email/domain). Идемпотентность батчей: потерянный ответ после коммита не создаёт дубликатов.

### 2.4 Надёжность джоб

Аренда джобы с продлением (`CONNECTOR_JOB_LEASE_SECONDS=180`), heartbeat коннекторов, `stale_after=120s`, ограниченное число повторов (`CONNECTOR_JOB_MAX_ATTEMPTS=3`) с восстановлением после рестарта коннектора. Ошибки провайдера попадают в job summary как partial scan, а не как «чистый пустой результат».

**Оценка: сильная, production-grade.** Единственное замечание — нет изоляции ресурсов самих коннектор-контейнеров уровня «скан не съел CPU» сверх mem/cpids-лимитов Compose.

---

## 3. Развёртывание

### 3.1 Форма инсталляции

Единственная форма — `docker-compose.yml` (9 сервисов: postgres, redis, backend, celery-worker, celery-beat, 3 коннектора, frontend) + отдельный сервис `backup`. Dev-overlay (`docker-compose.dev.yml`) — только для тестов/линта, «bare `docker compose up`» его не подхватит. `setup.py` — wizard без единой зависимости (только stdlib): генерирует все секреты из CSPRNG, проверяет файл по production-правилам до записи, никогда не печатает секреты (только отпечаток), умеет `--check` / `--repair` / `--force` (ротация с переносом старых ключей в `*_PREVIOUS_*`).

### 3.2 Сетевая сегментация

Три сети Docker:

| Сеть | Участники | Назначение |
|---|---|---|
| `opendrp-edge` | frontend ↔ backend | интернет-фейсинговый хоп |
| `opendrp-net` | backend, workers, PostgreSQL, Redis | данные; **коннекторов нет** |
| `opendrp-connectors` | backend ↔ коннекторы | коннектор физически не может открыть сокет к БД/брокеру |

Redis за `--requirepass`, порты БД/Redis привязаны к loopback по умолчанию (opt-in наружу). Терминация TLS — внешняя (работающий `reverse-proxy.example.conf` с самоподписанным сертификатом в комплекте); HSTS выключен по умолчанию осознанно.

### 3.3 Харденинг контейнеров

Backend: multi-stage, unprivileged user, `read_only: true` корневая ФС, `tmpfs /tmp noexec`, `cap_drop: ALL`, `no-new-privileges`, mem/cpu/pids-лимиты на каждый сервис. Логи — stdout, bounded json-file (10 MB × 5) с documented-путём смены на gelf/syslog-драйвер. Healthchecks на всех сервисах, включая celery (round trip через брокер, а не «процесс жив») и коннекторы (watchdog-файл). Гейт `scripts/check_compose_healthchecks.py` не даёт этим настройкам отвалиться.

### 3.4 Данные, бэкапы, миграции

- `make backup` / `backup-verify` / `restore`: dump + хранилище отчётов + read-back-проверка; restore защищён `CONFIRM_RESTORE=yes`, проверкой отсутствия клиентов, снимает safety-copy.
- Restore-путь **прогоняется в CI на каждый push** (dump мигрированной БД → восстановление в чистовую) — то есть «бэкап работает» доказано, а не декларировано.
- Retention: ночная уборка аудита (`AUDIT_RETENTION_DAYS`, по умолчанию 365) и отчётов; удаление батчами, факт — записью `audit.retention.purged` (домохозяйство отличимо от деструкции).
- Миграции: advisory lock wrapper `scripts.migrate.py`, гейты `check_migrations.py` (одна голова, целостная родословная) и `check_schema_drift.py` (модели↔схема).

### 3.5 CI/CD и релизы

CI (`ci.yml`): `backend` (suite + покрытие + ruff/mypy/compile), `production-integration` (реальные PostgreSQL/Redis: миграции, паритет схемы, интеграционные граничные тесты), `frontend` (typecheck, vitest, production build), `compose` (валидация формы + healthcheck-гейт), `repo-hygiene` (tracked-sources, portable-commands, env-template, version-consistency), `secrets` (gitleaks по **всей истории**), `codeql`, `security` (pip-audit, npm audit --omit=dev, bandit medium/medium). Все действия запатированы по commit SHA.

Release (`release.yml` на тег `v*`): сверка тега с `backend/app/__init__.py` → сборка и пуш 5 образов в GHCR с **SBOM + provenance attestation** → Trivy-скан каждого опубликованного образа, fail на unfixed HIGH/CRITICAL → GitHub Release с заметками из CHANGELOG. Релиз `v0.1.1` прошёл этот конвейер целиком зелёным.

**Оценка: сильная.** Комментарий: CI-джоба `backend` с таймаутом 40 минут уже один раз срывалась по таймауту на медленном раннере — запас прочности мал.

### 3.6 Масштабирование — честная оговорка

Ядро stateless и за балансировщиком масштабируется (подтверждено сценарием `make verify-replicas`: логин на одной реплике, токен/CSRF на второй, advisory lock на миграциях). Но:

1. **Compose-форма — одна узловая.** Нет helm/k8s-манифестов, PostgreSQL и Redis — single-instance без репликации. Для целевого сегмента (small/medium self-hosted) это осознанный компромисс, задокументированный в `docs/production-readiness.md`.
2. **celery-beat — один экземпляр** (иначе двойные сканы; Redis-дедуп снимает это в пределах минуты).
3. **`reports_store` — локальный каталог**, PDF не реплицируются между узлами (бэкап их покрывает).
4. Rate-limiter при недоступности Redis **fail-open** (осознанно: лучше без троттлинга, чем без операторов; внешний предел — nginx).

---

## 4. Кибербезопасность

### 4.1 Аутентификация и сессии

| Контрол | Реализация |
|---|---|
| Пароли | bcrypt (12 раундов), явный тронкейт 72 байта (обратная совместимость со старыми хешами; passlib/python-jose заменены как небезопасные) |
| Токены | PyJWT, HS256/384/512 в allowlist (`none` и асимметричные идентификаторы невозможны), `exp` обязателен |
| Refresh | БД-семьи с ротацией и **reuse detection** (повторное использование отзывает всю семью); хранение в `HttpOnly`/`Secure`/`SameSite=Lax` cookie |
| CSRF | double-submit cookie (`opendrp_csrf` + `X-CSRF-Token`, `compare_digest`), `SameSite=Lax` как второй слой |
| Брутфорс | Redis rate limit на логин + БД-lockout; **все ответы логина идентичны** (анти-enumeration), причина — только в аудит |
| Аккаунты | временные пароли (`must_change_password`) с onboarding-гейтом в `get_current_user`; политика паролей 12–72 байта |
| MFA | TOTP RFC 6238 (проверен по тест-векторам RFC), шифрование секретов Fernet, single-use с защитой от replay, в lockout засчитывается как неверный пароль; `REQUIRE_MFA_FOR_ADMINS` — обязательность на входе (не на админ-роутах), с onboarding-шагом; админский сброс с `must_enrol_mfa` (recovery не может быть лёгким способом снять MFA) |
| Троттлинг | `AUTHENTICATED_RATE_LIMIT_PER_MINUTE=600` в `get_current_user` (новый роут наследует автоматически) |

Все критические пути закрыты тестами (`test_auth*`, `test_mfa`, `test_onboarding`, `test_login_enumeration`, `test_credential_hardening`, `test_key_rotation`).

### 4.2 Секреты

- Нет ни одного хардкода: секреты только из env; в проде отвергаются placeholder-подобные значения (`change-me`, `yourstrong` и т.п.).
- Ротация без потерь: `ENCRYPTION_KEY` + `ENCRYPTION_PREVIOUS_KEYS` (MultiFernet: новейший шифрует, все расшифровывают), `JWT_SECRET_KEY` + `JWT_PREVIOUS_SECRET_KEYS`; `scripts/rotate_keys generate|status|rewrap` — трёхшаговая проверяемая процедура.
- Секреты настроек (SMTP-пароль, токен Telegram, адреса) шифруются Fernet at-rest и не возвращаются в plaintext.
- Токены коннекторов: 256-бит CSPRNG, в БД только SHA-256-дайджест, constant-time сравнение, ротация/отзыв per-connector; plaintext печатается один раз. Платформенного общего секрета коннекторов нет принципиально.

### 4.3 Инъекции и валидация ввода

- SQL: SQLAlchemy с bound parameters; `text(f"SELECT…")` в рантайме запрещён **тестом-гейтом** (`test_security_boundaries` сканирует исходники). Динамические идентификаторы (тестовые чистки) идут через whitelist `safe_sql_identifier`.
- Внешний ввод (Shodan/HIBP/коннекторы): Pydantic-валидация всех полей находок, контроль-символы отвергаются, `attributes` ограничен по числу ключей и форме; «лишние» поля отвергаются, а не переписываются.
- XSS: CSP `default-src 'self'; script-src 'self'` (без unsafe-inline для скриптов), `X-Content-Type-Options`, `X-Frame-Options`, `frame-ancestors 'self'`.
- Path traversal: `reports.file_path` — имя артефакта, не путь; единственная реализация containment (`artifact_path.py`) для API, задачи и retention; нарушение — отказ + аудит `report.artifact.rejected`.
- SSRF: `app/core/outbound.py` для всех исходящих соединений (SMTP, Telegram, WHOIS) отвергает loopback, cloud metadata, multicast/link-local, собственные сети деплоя; allowlist `OUTBOUND_ALLOWED_HOSTS` для внутреннего релея; отказы аудируются как `outbound.blocked` с разрешённым адресом.

### 4.4 Аудит и целостность

- Формат строго по требованию AGENTS.md: JSON-строка с ровно пятью полями `timestamp, user_id, action, ip_address, details` (пересборка по фиксированному списку полей перед рендером — тестово закреплено); `LOG_LEVEL` не может замолчать трейл (логгер закреплён на INFO).
- `X-Request-ID` сквозной: HTTP → Celery → логи → `details.request_id` (внутри `details`, чтобы не расширять контракт SIEM-индекса).
- **Хеш-цепочка аудита** (`audit_chain.py`, 524 строки): HMAC каждой записи (5 полей + хеш предыдущей + отпечаток ключа), монотонный `seq`, ключ из env (не из БД, которую защищает), ночная верификация с записью `audit.chain.verified/broken` в сам трейл, `GET /audit/integrity`, CLI-верификация экспортированного NDJSON без БД. Честно задокументирована граница: атакующий с записью в БД **и** чтением env перепишет историю — вторая копия (stdout → SIEM) есть то, что это обнаруживает.

### 4.5 Supply chain и статический анализ

pip-audit (runtime requirements) + npm audit --omit=dev как CI-гейты, bandit medium/medium, gitleaks по всей истории, CodeQL, Trivy на опубликованных образах с fail на unfixed HIGH/CRITICAL, SBOM + provenance, пины actions по SHA, Dependabot (pip/npm/docker/actions, группировка minor+patch, мажоры — сознательно отложены).

### 4.6 Открытые security alerts (Dependabot, на 2026-09-28)

**21 открытая: 2 critical, 4 high, 14 medium, 1 low.** Разбор шести верхних:

| Sev | Пакет | Scope | Суть | Комментарий |
|---|---|---|---|---|
| critical | anyio | **dev** (`requirements-dev.txt`) | TLS-спуфинг через IDNA-2003 кодирование hostname | dev-only; чинится обновлением dev-набора |
| critical | vitest | dev | Vitest UI server: чтение/исполнение файлов | dev-only, требует мажорного апдейта линейки |
| high | starlette ×3 | runtime (по `pyproject.toml`) | DoS через `request.form()` limits; SSRF/NTLM через UNC в StaticFiles (Windows); O(n²) DoS в FileResponse Range | **см. §5.1 — манифест врёт** |
| high | vite | dev | `server.fs.deny` bypass (Windows) | dev-only |

Плюс 14 medium: react-router 6 (runtime, фикс только в 7.x — задокументировано), pycares (runtime, уведомление на уже пиновую 4.9.0? — проверить), starlette ×3, pytest ×2, vite/vitest/esbuild/@vitest-mocker (dev).

---

## 5. Фреймворки и зависимости

### 5.1 Критическая находка: двойной манифест зависимостей

`backend/requirements.txt` (что реально уходит в прод-образ) и `backend/pyproject.toml` (Poetry) **разошлись**:

| Пакет | requirements.txt (прод) | pyproject.toml (Poetry) |
|---|---|---|
| fastapi | `==0.141.1` | `^0.115.0` |
| starlette | `==1.6.0` (явный пин!) | транзитивно от fastapi 0.115 → **другая ветка** |
| python-dotenv | `==1.2.2` (с комментарием про PYSEC-2026-2270) | `^1.0.1` (уязвимая!) |
| pytest | dev: `==8.3.2` | dev: `^8.3.2` |

Следствие — **Dependabot для pip смотрит в `pyproject.toml`**, поэтому3 HIGH-starlette alert'а отражают старую Poetry-резолюцию, а не то, что в образе; и наоборот, обновления Dependabot приходят в манифест, который прод-сборка не читает. Это и шум, и слепая зона контроля. **Рекомендация №1 аудита: привести манифесты к одному источнику правды** (либо удалить Poetry-зависимости, либо генерировать requirements из lock).

### 5.2 Стек и его состояние

| Компонент | Версия/статус |
|---|---|
| FastAPI / Starlette / Uvicorn | 0.141.1 / 1.6.0 / 0.30.6 — свежие, оба пина с обоснованием в комментариях (14 прошлых advisories) |
| SQLAlchemy 2.0 (async) + asyncpg / psycopg2-binary | 2.0.35 / 0.29.0 / 2.9.9 |
| Pydantic 2.9 + pydantic-settings | актуальная ветка |
| PyJWT 2.14 + bcrypt 5.0 + cryptography 50.0.1 | осознанные замены небезопасных python-jose/passlib |
| Celery 5.4 + redis 5.0.8 + msgpack 1.2.1 (фикс GHSA) | актуальные |
| Jinja2 3.1.6 (фикс sandbox-escape), fpdf2, structlog, tenacity | пины с ревизионными комментариями |
| React 18.3 + Vite 5.4 + TS 5.6 | стабильные |
| **Tailwind `4.0.0-beta.3`** | **бета в прод-цепочке сборки** — риск нестабильности |
| react-router-dom 6.26 | medium advisories, фикс только в 7.x (major-миграция отложена осознанно) |

Общая культура зависимостей высокая: точные пины, комментарии «какой CVE закрывает», dev-зависимости не попадают в прод-образ (отдельный `requirements-dev.txt` + build-arg), рантайм-аудит в CI.

---

## 6. Тестирование

- **Backend:** 94 файла тестов, **~1327 тест-функций**; юнит + интеграционные (API, аудит-цепочка, MFA, onboarding, коннекторы, ротация ключей, database limits, production-integration на реальных PostgreSQL/Redis с `REQUIRE_INTEGRATION=1`). Соответствует требованию TDD из AGENTS.md.
- **Frontend:** 32 тест-файла vitest (страницы, api, store, audit, moduleGraph) + production build с отказом на циклические импорты.
- **Покрытие:** ~92% `app/` (замер baseline), **пороговые гейты на 14 критичных модулях** (`check_critical_coverage.py`) — сильный агрегат не спрячет слабую границу (security 100%, connector_credentials 97.1%, request_rate_limit 92.3%...). Замер только с `COVERAGE_CORE=sysmon` (задокументированная особенность).
- **Гейты качества:** ruff, mypy (ratchet), compileall, граф Alembic, drift ORM↔схема, гейты репозитория (env-шаблон, переносимость команд, tracked sources, консистентность версии).
- **Задокументированные пробелы:** suite на SQLite (PostgreSQL-специфика — отдельными таргетами); двухрепличный сценарий — локальный, не CI; CodeQL не работал в приватном репо (сейчас репозиторий публичный и CodeQL в CI есть).

Известный долг тестов: `TODO(refactor-step-*)` — пины отсутствия transition-гардов в job lifecycle и порядка гардов; закрытие этих refactor-шагов повысило бы инварианты.

---

## 7. Наблюдаемость

Структурные JSON-логи (structlog) всех сервисов в stdout; аудит — дубль в stdout + БД; пять полей с точностью до контракта; `X-Request-ID` сквозной; `internal:`-префикс для системных событий; bounded docker-логи; `GET /health` (liveness без зависимостей) и `GET /ready` (PostgreSQL + Redis); healthchecks Compose; `docs/observability.md` с путём в Elastic Security/Vector/log-driver. Метрик (Prometheus) и трейсинга (OTel) **нет** — для целевого сегмента приемлемо, но это первый шаг при выходе за пределы small/medium.

---

## 8. Сводка рисков и рекомендации

| # | Риск | Серьёзность | Рекомендация |
|---|---|---|---|
| R1 | Рассинхрон `requirements.txt` ↔ `pyproject.toml`; Dependabot мониторит не то, что уходит в образ | **высокая** (слепая зона supply chain) | Один источник правды; после этого — закрыть реальные alerts |
| R2 | 21 открытая security alert (2 critical, 4 high), из них3 HIGH формально runtime | высокая | Закрыть обновлениями: anyio/vitest/vite (dev-линейки), starlette (после R1 проверить реальную экспозицию), react-router 7 |
| R3 | CodeQL v3 устареет в декабре 2026, поле `language` → `languages` (предупреждения на каждом прогоне) | средняя | Переход на CodeQL v4 |
| R4 | Таймаут backend-джобы CI 40 мин однажды сорвал прогон | средняя | Поднять timeout или разбить джобу |
| R5 | `alembic check` не проходит: 5 лишних unique-констрейнтов + 4 недекларированных индекса | средняя (ляжет в первую autogenerate-миграцию) | Декларировать индексы в моделях, убрать дубли из baseline **до** первой autogenerate |
| R6 | Tailwind `4.0.0-beta.3` в прод-сборке | средняя | Перейти на стабильный Tailwind 4.x |
| R7 | Нет HA: single PostgreSQL/Redis, один beat, локальный reports_store | низкая (осознанный компромисс сегмента) | Задокументировать эволюцию: внешний managed PG/Redis, объектное хранилище отчётов |
| R8 | Rate-limiter fail-open при отказе Redis | низкая (задокументировано) | Оставить; мониторить доступность Redis |
| R9 | Рукописный API-клиент фронтенда (строковые пути) | низкая | Генерация клиента из `/openapi.json` |
| R10 | Нет метрик/трейсинга | низкая | Prometheus + OTel при росте нагрузки |
| R11 | Рефакторинг-долг тестов (`TODO(refactor-step-*)`: transition-guards джоб) | низкая | Закрыть шаги 1/2/5 |

---

## 9. Соответствие внутренним требованиям (AGENTS.md)

| Требование | Статус |
|---|---|
| Stateless + горизонтальное масштабирование | ✅ ядро stateless, verify-replicas; ⚠️ инфраструктура single-node |
| Пулы соединений PostgreSQL | ✅ asyncpg pool (20+10, LIFO, recycle), `503 database_busy` при насыщении |
| Core не зависит от конкретных коннекторов, унифицированные интерфейсы | ✅ self-declared manifest, модули как данные |
| Secure by Design, строгая валидация внешнего ввода | ✅ Pydantic на всех границах (пользователи + Shodan/HIBP) |
| Защита от SQL-инъекций (ORM/параметры) | ✅ + тест-гейт против f-string SQL |
| Нет хардкода секретов | ✅ env-only, CSPRNG в wizard, отвержение placeholder'ов |
| JSON-аудит `timestamp/user_id/action/ip_address/details` | ✅ контракт закреплён тестами, + HMAC-цепочка |
| TDD, покрытие бизнес-логики и интеграций | ✅ ~1327 бэкенд-тестов, интеграционные на реальных PG/Redis, пороги покрытия |

---

*Методика: статический анализ исходников (backend/app, connectors, frontend/src, docker, .github), README/документации, CI/CD workflow, манифестов зависимостей, Compose-топологии, а также выборочная проверка состояния репозитория и GitHub security alerts (API) на дату аудита. Числовые замеры тестов/покрытия — по данным `docs/production-readiness.md` и текущему дереву; перед релизом перепроверять командами из раздела «Reproducing the numbers» этого документа.*
