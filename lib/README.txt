# Библиотеки для Zereans Applet

В эту папку необходимо поместить следующие JAR файлы:

## Обязательные библиотеки:

1. **api.jar** - Java Card API (обычно находится в Java Card SDK)
   - Путь: `$JAVA_HOME/lib/javacard/api.jar`

2. **converter.jar** - Java Card Converter (для конвертации в CAP)
   - Путь: `$JAVA_HOME/lib/javacard/converter.jar`

3. **offcardverifier.jar** - Off-card Verifier (опционально)
   - Путь: `$JAVA_HOME/lib/javacard/offcardverifier.jar`

## Установка Java Card SDK:

1. Скачайте Java Card Development Kit с официального сайта Oracle
2. Установите SDK в директорию (например, `C:\JavaCard\`)
3. Скопируйте необходимые JAR файлы в папку `lib/`

## Альтернативный способ:

Если у вас установлен Java Card SDK, вы можете изменить пути в `build.xml`:

```xml
<property name="jc.sdk" value="C:\JavaCard\lib\javacard"/>
```

Замените `C:\JavaCard\` на путь к вашему Java Card SDK.
