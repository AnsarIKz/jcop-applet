## Подготовка unfused карточек к production

Ниже — конкретные шаги: как идентифицировать наши unfused карты, какие ключи им нужны, как генерировать серверные ключи и как выпустить персонализационный пакет APDU для загрузки данных на карту.

### Идентификация карты

- **ATR**: проверьте ATR в любом PC/SC инструменте. Наши карты определяются по AID апплета.
- **AID апплета**: `A0:00:00:00:62:03:01:0C:06` (см. `README.md`). Выполните SELECT по AID:
  - CAPDU: `00 A4 04 00 09 A0 00 00 00 62 03 01 0C 06 00`
  - Успешный `SW=9000` подтверждает наличие нашего апплета.

### Признаки unfused состояния

- Карта не инициализирована командой `INS_INITIALIZE (0x01)`.
- Команда `INS_GET_STATUS (0x05)` возвращает статус «неинициализировано» (зависит от реализации, см. вашу текущую сборку апплета).
- Обновление ключей `INS_UPDATE_KEYS (0x06)` допустимо без предварительной смены политики (для production карт политика может требовать аутентификацию).

### Набор ключей и материалов

- **Ключ аутентификации карты**: `master_auth_key` (симметричный, 16 или 32 байта, hex).
- **Сессионный ключ**: `session_key` (симметричный, 16 или 32 байта, hex).
- **Серверная пара ключей**: ECDSA P-256 (для подписей/проверок на стороне сервера и/или при персонализации).
- **База карт**: `card_keys.db` — TSV/CSV с колонками: `card_id`, `uid`, `master_auth_key_hex`, `session_key_hex`, `server_pubkey_hex`.

Файлы по-умолчанию в репо:

- `master_auth_key.hex` — пример ключа (hex, 32 байта в 64 символах)
- `session_key.hex` — пример ключа (hex, 32 байта в 64 символах)
- `card_keys.db` — пример реестра карт

### Генерация серверных ключей

Сгенерируйте ECDSA P-256 пару. Вы получите `server_key.pem` (приватный) и `server_pub.pem` (публичный), а также «сырой» hex публичного ключа для включения в профили карт.

```bash
pwsh ./tools/gen-server-keys.ps1 -OutDir ./secrets
```

Результат:

- `secrets/server_key.pem`
- `secrets/server_pub.pem`
- `secrets/server_pub_raw.hex` — публичный ключ в сжатом формате (33 байта, hex) для TLV

### Генерация ключей для конкретной карты

Для каждой карты создайте уникальные симметричные ключи и профиль персонализации.

```bash
pwsh ./tools/gen-card-keys.ps1 -CardId 0102030405060708 -OutDir ./secrets/cards
```

Результат (в `./secrets/cards/0102030405060708/`):

- `master_auth_key.hex`
- `session_key.hex`
- `card_profile.json` — агрегированный профиль
- Автоматическая запись/обновление строки в `card_keys.db`

### Формат персонализационного TLV

Используем простой TLV для полезных данных APDU, чтобы сохранять совместимость и читабельность:

- `0x5A` — `CARD_ID` (8 байт)
- `0x81` — `MASTER_AUTH_KEY` (16 или 32 байта)
- `0x82` — `SESSION_KEY` (16 или 32 байта)
- `0x91` — `SERVER_PUBKEY` (33 байта сжатый secp256r1)

Пример полезной нагрузки для `INS_INITIALIZE (0x01)` — минимум `CARD_ID`:

```text
5A 08 <8 байт card_id>
```

Пример полезной нагрузки для `INS_UPDATE_KEYS (0x06)`:

```text
81 10 <16/32 байт master_auth_key> 82 10 <16/32 байт session_key> 91 21 <33 байта server_pubkey>
```

Примечание: если ваша сборка апплета требует иной порядок или теги — обновите генератор TLV в скрипте персонализации.

### Подготовка APDU-скрипта персонализации

Создайте APDU-скрипт, который можно исполнить любым инструментарием, поддерживающим «скриптовое» выполнение CAPDU (например, через GlobalPlatformPro, SCardControl, внутренние тулзы).

```bash
pwsh ./tools/make-personalization.ps1 -CardId 0102030405060708 -OutDir ./out
```

Результат (в `./out/0102030405060708/`):

- `personalize.apdu` — последовательность APDU:
  1. SELECT AID
  2. `INS_INITIALIZE` с `CARD_ID`
  3. `INS_UPDATE_KEYS` с ключами и публичным ключом сервера

Содержимое `personalize.apdu` — строки с hex APDU в формате:

```text
00A4040009A00000006203010C0600
80010000<Lc><payload_hex>00
80060000<Lc><payload_hex>00
```

### Полная процедура выпуска

1. Сгенерировать серверные ключи: `pwsh ./tools/gen-server-keys.ps1 -OutDir ./secrets`
2. На каждую карту:
   - Считать (или назначить) `card_id` (8 байт). Рекомендуется использовать читаемый серийник или UID карты.
   - `pwsh ./tools/gen-card-keys.ps1 -CardId <HEX_8B> -OutDir ./secrets/cards`
   - `pwsh ./tools/make-personalization.ps1 -CardId <HEX_8B> -OutDir ./out`
3. Установить CAP (см. `README.md` / Ant `convert`, далее установка через ваш GlobalPlatform тулчейн).
4. Выполнить `personalize.apdu` на карте.
5. Зафиксировать запись в `card_keys.db` и в CI/CD секретах сервера.

### Установка CAP на карту (Windows / PowerShell)

```powershell
# Сборка CAP
ant convert

# Установка через GlobalPlatformPro (gp.jar положите в tools/)
pwsh ./tools/install-cap.ps1 -GpJar ./tools/gp.jar -Key 404142434445464748494A4B4C4D4E4F -InstanceAID A00000006203010C06
```

### Установка CAP на карту (Linux)

```bash
ant convert
./tools/install-cap.sh ./tools/gp.jar ./build/*.cap 404142434445464748494A4B4C4D4E4F A00000006203010C06
```

### Linux команды (эквиваленты)

```bash
# 1) Серверные ключи
./tools/gen-server-keys.sh ./secrets

# 2) Ключи для карты (CardId = 8 байт в hex, 16 символов)
./tools/gen-card-keys.sh 0102030405060708 ./secrets/cards ./card_keys.db ./secrets/server_pub_raw.hex

# 3) APDU-скрипт персонализации
./tools/make-personalization.sh 0102030405060708 ./secrets/cards ./out
```

### Политика хранения секретов

- Храните приватные ключи сервера только в защищённом хранилище (например, KMS или Hardware-backed Vault).
- Файлы `*.hex` с ключами держите вне VCS.
- На проде ключи подтягивайте через переменные окружения/секреты.

### Тестовый прогон (стенд)

- Используйте тестовые ключи и отдельный `card_keys.db`.
- Проверяйте `INS_AUTHENTICATE (0x02)` и `INS_VERIFY_SIGNATURE (0x07)` после персонализации.

### Пример моделей, схема Prisma

```
// schema.prisma
datasource db { provider = "postgresql"; url = env("DATABASE_URL") }
generator client { provider = "prisma-client-js" }

model Card {
  id                 String      @id @default(cuid())
  cardIdHex          String      @unique // 16 hex chars (8 bytes) by convention
  uidHex             String?     // физический UID, если читаем
  status             CardStatus  @default(ACTIVE)
  masterAuthKeyHash  String      // hash(key) или KMS ref, не хранить raw
  sessionKeyHash     String      // hash(key) или KMS ref, не хранить raw
  serverPubKeyHex    String      // 33-byte compressed P-256 hex
  // опционально: счет, лимиты, политика
  balanceMinor       BigInt      @default(0)
  createdAt          DateTime    @default(now())
  updatedAt          DateTime    @updatedAt

  transactions       Transaction[]
}

model Transaction {
  id                 String            @id @default(cuid())
  cardId             String
  card               Card              @relation(fields: [cardId], references: [id], onDelete: Restrict)
  kind               TransactionKind
  amountMinor        BigInt            // сумма в минимальных единицах
  nonceHex           String            // монотонный nonce/ctr, предотвращает replays
  cardSignatureHex   String            // подпись карты (если карта подписывает)
  serverSignatureHex String?           // подпись сервера (если 2-sided)
  status             TransactionStatus @default(PENDING)
  createdAt          DateTime          @default(now())
  committedAt        DateTime?

  @@index([cardId, createdAt])
  @@index([kind, createdAt])
}

enum CardStatus {
  ACTIVE
  BLOCKED
  REVOKED
}

enum TransactionKind {
  TOPUP
  PURCHASE
  REFUND
  ADJUST
}

enum TransactionStatus {
  PENDING
  CONFIRMED
  REJECTED
}
```
