# OCSERV AUTH CREDS COLLECTOR V1.0

### Зачем
Изначально было написано чтобы мониторить какие данные вводятся в интерфейс ханипота в виде OpenConnect server. 
К тому же, нужно было как то расшифровывать TLS трафик.

### Установка
 1. `sudo nano /etc/ocserv/ocserv.conf`
 2. Изменить значение: `tls-priorities="NONE:+VERS-TLS-ALL:+MAC-ALL:+RSA:+AES-128-CBC:+SIGN-ALL:+COMP-NULL"`. Это нужно для того, чтобы принудительно установить cipher-suite при TLS хендшейке в TLS_RSA_WITH_AES_128_CBC_SHA.
 3. `sudo apt install tshark`
 4. `pip3 install -r requirements.txt`
 5. EZ

### Запуск
Общий вид:  
`python3 ocacc.py MODE -i eth0 -I IP_ADDR -k KEYFILE`
где
 - IP_ADDR - Адрес сервера для фильтров TShark (Только входящие пакеты)
 - KEYFILE - Закрытый ключ ocserv (server-key.pem by default). Желательно создать символьную ссылку до него и использовать как `-k server-key.pem`

Возможен запуск в режиме:
 - live `MODE = live`.
 - демона `MODE = daemon`. [Пример сервиса systemd](./ocacc.service)
 - cron задачи `MODE = cron`. [Пример bash скрипта для cron](./cron_task.sh)


<!--
### TODO:
 - [X] Базовый функционал
 - [ ] Извлекать IP из имени интерфейса.
 - [ ] Переделать логгирование.
 - [ ] Переделать "разбор" пакета ибо это не годится.
 - [ ] Привести out-файл к стандартизированному виду.
 - [ ] Очистка кода.
-->