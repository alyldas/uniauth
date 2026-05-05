Всегда отвечай пользователю по-русски, даже если код, логи и ошибки на английском.

Категорически запрещено упоминать служебное имя, бренд или происхождение агента в ветках, commit
messages, PR title/body, issues, labels, milestones, changelog, документации, комментариях к коду,
generated artifacts и обычных ответах пользователю. Не добавлять служебные префиксы в стиле имени
агента. Исключение: только технические директивы/метаданные, которые среда выполнения требует сама
и которые не являются содержанием репозитория, GitHub или пользовательского текста.

Команды gh CLI: при Full Access / `danger-full-access` запускай обычной командой; при Default
permissions или другом sandbox-режиме запускай вне песочницы с
`sandbox_permissions=require_escalated`; если escalation недоступен, не используй gh.

Во всех `.md` файлах использовать только относительные ссылки. Абсолютные файловые ссылки
запрещены.

Playwright: глобальный запрет на доступ к системному браузеру.

- Никогда не использовать системный Google Chrome, Microsoft Edge, обычный Chromium и любые их
  реальные пользовательские профили через Playwright.
- Разрешён только строго изолированный Playwright-managed Chrome for Testing.
- В MCP/config использовать `browserName: "chromium"` только как технический engine selector вместе
  с `isolated: true` и `launchOptions.channel: "chrome-for-testing"`. Plain `chromium` без явного
  Chrome for Testing запрещён.
- Запрещены `channel: "chrome"`, `chrome-beta`, `chrome-dev`, `chrome-canary`, `msedge*`,
  `chromium`, а также CLI-флаги `--channel chrome*`, `--browser-channel chrome*`,
  `--channel msedge*`, `--browser-channel msedge*` и plain `--browser=chromium`, если запуск не
  привязан к явно изолированному Chrome for Testing config.
- Запрещены `executablePath`, `connect()`, `connectOverCDP()`, `cdpEndpoint`, `remoteEndpoint`,
  browser extension bridge к существующим вкладкам браузера и любые подключения к already running
  system browser.
- Запрещены `launchPersistentContext()`, `--persistent`, `--profile`, любые `userDataDir`,
  указывающие на системные профили вроде `~/Library/Application Support/Google/Chrome`,
  `~/Library/Application Support/Microsoft Edge`, `%LOCALAPPDATA%/Google/Chrome/User Data` и
  аналогичные пути, а также любые не-isolated профили вообще.
- Если любой инструмент, тест, MCP-конфиг, навык, плагин или команда не может гарантировать именно
  Chrome for Testing + `isolated: true`, немедленно остановиться и не запускать такой сценарий
  вообще.

Если работа уходит в GitHub PR, перед `git push` обязательно прогоняй локально тот же класс
проверок, что и CI для затронутой области; если в CI есть отдельные `lint`, `test`, `build`,
локально нельзя ограничиваться только `test`.

Если изменения затрагивают TypeScript, backend bootstrap-path, env/config, тестовые mock-объекты или
import-time код, отдельный `build`/`tsc` обязателен даже при зелёных тестах.

После каждого `git push` в GitHub PR обязательно проверяй именно текущий `head SHA` через
`gh pr view --json headRefOid,statusCheckRollup` и дожидайся завершения checks через
`gh pr checks --watch` или эквивалент.

Запрещено писать пользователю, что PR или CI зелёные, что checks прошли или что работа готова, пока
GitHub не показывает `SUCCESS` для required checks на точном текущем `head SHA`.

Если любой GitHub check падает, обязан сразу снять failed logs, найти root cause, исправить, снова
запушить и заново дождаться зелёных checks; старый локальный green не имеет значения.

Если checks ещё `queued` или `pending`, это нужно называть именно `queued` или `pending`, а не
успешным результатом.

Категорически запрещено использовать `rm -rf` в любых обстоятельствах. Массовые удаления директорий
запрещены; удалять файлы можно только точечно, после явного перечисления путей и отдельного
подтверждения пользователя.
