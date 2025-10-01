# Zereans Applet - Core Files

Эта папка содержит все необходимые файлы для JavaCard апплета Zereans.

## Структура

```
/
├── src/                    # Исходный код апплета
│   └── com/zereans/applet/
│       ├── ZereansApplet.java      # Основной апплет
│       ├── SecurityManager.java    # Менеджер безопасности
│       ├── TransactionManager.java # Менеджер транзакций
│       └── NetworkProtocol.java    # Сетевой протокол
├── test/                   # Тесты
│   └── ZereansAppletTestClean.java
├── build/                  # Скомпилированные файлы
├── sdk/                    # JavaCard SDK
├── lib/                    # Библиотеки
├── build.xml              # Ant build script
├── run_tests.bat          # Скрипт запуска тестов
└── setup_environment.ps1  # Настройка окружения
```

## Сборка

```bash
# Перейти в папку inside
cd inside

# Очистка
ant clean

# Компиляция
ant compile

# Конвертация в CAP
ant convert

# Полная сборка
ant build

# Запуск тестов
ant test
```

## Установка на карту

1. Скомпилируйте проект: `ant build`
2. Используйте JavaCard Development Kit для установки CAP файла
3. Выберите апплет по AID: `A0:00:00:00:62:03:01:0C:06`

## Команды апплета

- `INS_INITIALIZE (0x01)` - инициализация (генерация ключей)
- `INS_AUTHENTICATE (0x02)` - аутентификация (challenge-response)
- `INS_TRANSACTION (0x03)` - транзакции (с подписью)
- `INS_GET_BALANCE (0x04)` - получение баланса
- `INS_GET_STATUS (0x05)` - статус
- `INS_UPDATE_KEYS (0x06)` - обновление ключей
- `INS_VERIFY_SIGNATURE (0x07)` - проверка подписи

## Безопасность

### Ключевые улучшения безопасности:

1. **Правильное управление ключами:**

   - Ключи генерируются только при инициализации
   - Использование KeyStore для безопасного хранения
   - Очистка чувствительных данных

2. **Атомарные транзакции:**

   - Rollback при ошибках
   - Проверка состояний
   - Валидация подписей

3. **Защита от атак:**
   - Challenge-response аутентификация
   - Проверка целостности данных
   - Ограничения на транзакции

### Проверка безопасности:

```bash
# Запуск валидации безопасности
ant security-check

# Полная проверка
ant full-security-test
```
