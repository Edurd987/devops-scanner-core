# DevOps Dependency Security Scanner — Core

CLI-утилита для анализа зависимостей проектов: поиск уязвимостей (CVE),
лицензионных рисков и технического долга с расчётом совокупного индекса риска.

## Возможности (Core, MIT)

- Парсинг манифестов: `requirements.txt` (Python), `package.json` (Node.js)
- CVE Engine: сопоставление версий с известными уязвимостями
- Risk Scoring по трём векторам: Security, License, Maintenance
- Вывод результатов в JSON

## Установка

```bash
git clone https://github.com/Edurd987/devops-scanner-core.git
cd devops-scanner-core
python dependency_scanner.py --help
```

## Лицензия

Core-сканер распространяется под лицензией MIT — см. [LICENSE](LICENSE).

## Коммерческая версия

Веб-интерфейс, Dashboard, аналитика, PDF-отчёты, API с аутентификацией
и облачное сканирование доступны как отдельный коммерческий продукт.
