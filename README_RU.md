[English](README.md) | Русский

# MikroTik REST MCP

MCP-сервер, дающий кодинг-агентам структурированный доступ к RouterOS 7 через REST API — чтение, фильтры, охраняемые мутации, откат по расписанию, shell в контейнеры и передача файлов. Один MCP-сервер по stdio.

Сделан для реальной эксплуатации: агент может инвентаризировать роутер, сличить состояние файрвола/маршрутов, зайти в контейнер, посмотреть счётчики и применять правки — с подтверждением от человека перед любой деструктивной операцией.

## Возможности

- **Широкое покрытие чтения**
  - ~60 курируемых тулов `get_*` для основных коллекций (файрвол, маршруты, DHCP, DNS, интерфейсы, WireGuard, контейнеры, шедулер, логи, ресурсы системы).
  - Ещё 200+ `get_*`-эндпоинтов вызываются по имени через тот же конвейер фильтров — намеренно не перечислены, чтобы схема тулов оставалась компактной. Найти их можно через `catalog_search`.
  - `routeros_get` принимает любой `/rest/`-путь, `routeros_batch` — до 16 параллельных чтений за вызов.
- **Настоящие фильтры**
  - Клиентский `where` с суффиксами `__contains`, `__in`, `__not`, `__gt`, `__gte`, `__lt`, `__lte`, `__startswith`, `__endswith`.
  - `fields` (проекция), `sort_by`, `limit`, `compact` (одна строка на элемент — экономит токены).
  - Проброс RouterOS-нативных `.proplist`/`.query` для серверной фильтрации.
- **Охраняемые мутации**
  - `MIKROTIK_MODE=readonly`: мутации/исполнительные тулы вообще не регистрируются — протокольная поверхность чисто read-only, а не просто под гейтом.
  - `MIKROTIK_MODE=careful` (по умолчанию): операции, классифицированные как деструктивные, возвращают `requires_confirmation` — агент показывает это пользователю и повторяет вызов с `confirm: true`. MCP elicitation даёт нативный диалог там, где поддерживается. **Флаг confirm — UX-гейт, не security boundary; реальная граница — права роутерного юзера.**
  - Method-aware политика: `PUT` только на известные коллекции, `PATCH`/`DELETE` только на `collection/<id>`, `POST` только по явному allowlist действий.
  - `MIKROTIK_STRICT_CONFIRM=1` — подтверждение каждой мутации.
  - `MIKROTIK_MODE=yolo` снимает все гейты и может переключаться на отдельный полноправный аккаунт (`MIKROTIK_YOLO_USERNAME` / `MIKROTIK_YOLO_PASSWORD_FILE`) — только для контролируемых окон автоматизации.
- **Откат по расписанию** (не RouterOS Safe Mode — работает поверх обычного REST)
  - `apply_safe` делает снапшот, ставит шедулер на роутере, потом применяет мутацию. После взведения откат не зависит от жизни MCP-процесса — `commit_safe` снимает его в течение `window_seconds`.
  - Поддержаны `PATCH` (восстановление снапшота изменённых полей — не транзакция, без детекции параллельных правок) и `DELETE` (best-effort recreate; позиция и сгенерированные поля теряются). `PUT` отклоняется: `.id` созданного объекта неизвестен до создания.
  - При неоднозначной транспортной ошибке откат остаётся взведённым, а не снимается молча; `commit_safe` сохраняет запись при неудаче снятия — можно повторить.
  - `safe_status` показывает активные откаты.
- **Контейнеры и диагностика**
  - `container_shell` — команды внутри контейнеров RouterOS — выключен по умолчанию (`MIKROTIK_ENABLE_CONTAINER_SHELL`), под confirm-гейтом в careful, и генерический `routeros_write` флаг не обходит.
  - `interface_traffic` — живые bps/pps за окно сэмплирования; `routeros_watch` — дельты числовых полей между сэмплами (счётчики без ручных вычитаний).
  - `run_ping`, `run_traceroute`, `run_fetch`, `run_wifi_monitor`, `describe_path` (интроспекция полей до написания фильтров).
- **Файлы в песочнице**
  - На роутере: create/read/update/rename/delete + chunked `download_file`/`upload_file`.
  - Доступ к ФС хоста выключен по умолчанию; `MIKROTIK_ENABLE_LOCAL_FILES` + `MIKROTIK_LOCAL_ROOT` ограничивают его одним каталогом; передачи капнуты на 8 МБ, `download_file` требует `overwrite: true` чтобы заменить существующий файл.
- **Гигиена секретов**
  - Креды через `MIKROTIK_PASSWORD_FILE` (рекомендуется) или `MIKROTIK_PASSWORD`.
  - Каждый ответ проходит через скраббер — поля вида `password`/`secret`/`psk`/`token`/`private-key` маскируются (`MIKROTIK_REDACT=0` выключает). Скраб по имени поля — секреты в свободном тексте (комменты, тела скриптов, логи, файлы) не детектируются.
  - Аннотации `readOnlyHint`/`destructiveHint`/`idempotentHint`/`openWorldHint` на всех тулах — клиент может резать свои пермишены.

## Требования

- Python **3.10+** (разработано на 3.13).
- RouterOS **7.1+** с доступным REST (интеграционно проверено на **7.24.5**, hAP ax³ — REST, контейнеры, откат через шедулер, файлы). HTTPS через `www-ssl` рекомендуется; голый HTTP через `www` работает с RouterOS **7.9+** и только в изолированной сети — REST ходит на Basic auth, читаемом в сегменте.
- Юзер с `read` + `api` + `rest-api` для чтения. Плюс `write`/`test` для мутаций и диагностики, `ftp` для файловых тулов (`download_file`, `/file/read`). У записей скриптов своё поле `policy` — аккаунту для запуска хватает `write`, и он не может исполнить скрипт с правами шире своих.

## Установка

```bash
pipx install mikrotik-rest-mcp-server   # или: uvx mikrotik-rest-mcp-server
```

Появится консольная команда `mikrotik-rest-mcp-server`. Для разработки: `git clone` + `pip install -e .`

## Конфигурация

```json
{
  "mcpServers": {
    "mikrotik_rest": {
      "command": "mikrotik-rest-mcp-server",
      "env": {
        "MIKROTIK_BASE": "https://192.168.88.1",
        "MIKROTIK_USERNAME": "mcp-agent",
        "MIKROTIK_PASSWORD_FILE": "/path/to/password-file"
      }
    }
  }
}
```

Полный список переменных — в `.env.example` (режимы, флаги возможностей, таймауты, проверка TLS).

### Рекомендуемый юзер на роутере

```routeros
# ops-аккаунт — чтение, правки конфига, диагностика; без управления юзерами,
# без sensitive-полей, без ребута
/user group add name=agent policy=read,write,api,rest-api,test,ftp
/user add name=mcp-agent group=agent password=<random>

# только мониторинг (в паре с MIKROTIK_MODE=readonly)
/user group add name=monitor policy=read,api,rest-api,test
```

Для `yolo` — второй аккаунт в `full` через `MIKROTIK_YOLO_*`. Если файловые тулы не нужны, `ftp` можно не давать.

## Работа с агентами

Типичный поток:

```
get_dhcp_leases {compact: true}                     → быстрый список устройств
routeros_batch {requests: [...]}                    → статус за один вызов
describe_path {path: "/rest/interface/ethernet"}    → имена полей до фильтров
interface_traffic {name: "ether1", seconds: 2}      → живой throughput
routeros_watch {path: ..., diff: true}              → дельты счётчиков
routeros_write {method: "PATCH", ...}               → обычная правка
routeros_write {method: "DELETE", ...}              → остановится за подтверждением
apply_safe {method: "PATCH", path: ..., window_seconds: 60}
                                                    → откат взведён на роутере; commit_safe чтобы оставить
```

`run_script_inline` создаёт временный RouterOS-скрипт, выполняет и удаляет его (в careful всегда спрашивает). `container_shell` и передача файлов на хост — по флагам.

## Структура

```text
src/mikrotik_rest_mcp/
  client.py      — REST-транспорт, TLS, env-конфиг
  catalog.py     — таблицы эндпоинтов/тулов (чистые данные)
  policy.py      — риск-уровни, confirm-гейт, allowlist мутаций
  output.py      — скраббер секретов, фильтры, компакт-сериализация
  files.py       — песочница локальных файлов + роутерные хелперы
  safe_apply.py  — машинерия снапшота/отката
  server.py      — список тулов, диспатч, ресурсы, entrypoint
```

## Тесты

```bash
pytest tests/
```

Юнит-тесты не требуют роутера (REST замокан).

## Безопасность

См. `SECURITY.md`. Не направлять на чужие роутеры; `yolo` — заряженное ружьё, а `container_shell` — это remote code execution (он и есть).
