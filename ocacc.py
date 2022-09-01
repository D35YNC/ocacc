import datetime
import json
import logging
import os
import sys
import xml.etree.ElementTree as ET

import pyshark


def init_logger(debug):
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG if debug else logging.INFO)

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setLevel(logging.DEBUG)
    stream_handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)-8s %(message)s"))
    logger.addHandler(stream_handler)

    file_handler = logging.FileHandler("/var/log/ocacc.log")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)-8s %(message)s"))
    logger.addHandler(file_handler)
    logger.info("INIT")

    return logger


def default_process(args):
    logger = init_logger(args.debug)
    dirname = os.path.join(os.path.dirname(os.path.abspath(__file__)), datetime.datetime.now().strftime("%d.%m.%Y_%H-%M-%S"))
    try:
        os.mkdir(dirname)
    except OSError:
        logger.error("Cant create folder", exc_info=True)
    else:
        logger.debug(f"Directory {dirname} created")

    logger.debug("Init pyshark.LiveCapture()")
    capture = pyshark.LiveCapture(args.interface,
                                  display_filter=f'ip.dst == {args.ip} and http contains "auth HTTP"',
                                  override_prefs={"ssl.keys_list": f"{args.ip},{args.port},http,{args.keyfile}"})

    creds = {}
    # creds[IP][SESSION(TCP.SRCPORT)] = {"username":"", "passwords":[]}
    logger.info("Starting capture")
    try:
        for packet in capture.sniff_continuously():
            logger.info(f"Login attempt? from {packet.ip.src}")

            xml = str(packet.http.file_data)
            tree = ET.ElementTree(ET.fromstring(xml)).getroot()

            if not creds.get(packet.ip.src):
                creds[packet.ip.src] = {0: {"username": "", "passwords": []}}
            if not creds[packet.ip.src].get(packet.tcp.srcport):
                creds[packet.ip.src][packet.tcp.srcport] = {"username": "", "passwords": []}

            if "password" in xml:
                creds[packet.ip.src][packet.tcp.srcport]["passwords"].append(tree.find("auth/password").text)
                logger.info(f"New creds part from {packet.ip.src}:{packet.tcp.srcport}: password: {tree.find('auth/password').text}")
            else:
                creds[packet.ip.src][packet.tcp.srcport]["username"] = tree.find("auth/username").text
                logger.info(f"New creds part from {packet.ip.src}:{packet.tcp.srcport}: username: {tree.find('auth/username').text}")
    except Exception as ex:
        logger.warning(f"Exit bec: {ex}")
        with open(os.path.join(dirname, "extracted_creds.json"), 'w', encoding='utf-8') as creds_file:
            json.dump(creds, creds_file)


def cron_process(args):
    logger = init_logger(args.debug)
    dirname = os.path.join(os.path.dirname(os.path.abspath(__file__)), datetime.datetime.now().strftime("%d.%m.%Y_%H-%M-%S"))
    try:
        os.mkdir(dirname)
    except OSError:
        logger.error("Cant create folder", exc_info=True)
    else:
        logger.debug(f"Directory {dirname} created")

    logger.info(f"Loading {args.pcap_file}")
    logger.debug("Init pyshark.FileCapture")
    capture = pyshark.FileCapture(args.pcap_file,
                                  display_filter=f'ip.dst == {args.ip} and http contains "auth HTTP"',
                                  override_prefs={'ssl.keys_list': f"{args.ip},{args.port},http,{args.keyfile}"})
    creds = {}
    # creds[IP][SESSION(TCP.SRCPORT)] = {"username":"", "passwords":[]}
    for packet in capture:
        xml = packet.http.file_data.replace("\\xa", "")
        tree = ET.ElementTree(ET.fromstring(xml)).getroot()
        if not creds.get(packet.ip.src):
            creds[packet.ip.src] = {packet.tcp.srcport: {"username": "", "passwords": []}}
        if not creds[packet.ip.src].get(packet.tcp.srcport):
            creds[packet.ip.src][packet.tcp.srcport] = {"username": "", "passwords": []}

        if "password" in xml:
            creds[packet.ip.src][packet.tcp.srcport]["passwords"].append(tree.find("auth/password").text)
        else:
            creds[packet.ip.src][packet.tcp.srcport]["username"] = tree.find("auth/username").text

    if creds:
        with open(f"{dirname}/extracted_creds.json", 'w', encoding="utf-8") as out_creds_file:
            out_creds_file.write(json.dumps(creds))
        logger.info(f"Extracted {len(creds)} IPs and {sum([len(creds[x]) for x in creds])} sessions")
    else:
        logger.info(f"Nothing is extracted")

    capture.close()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["live", "daemon", "cron"], help="work mode.")
    parser.add_argument("-i", "--interface", type=str, metavar="if", help="Interface for listening to TShark", default="eth0")  # Daemon+Live
    parser.add_argument("-I", "--ip", type=str, metavar="ip", help="Server IP address for TShark filter", default="127.0.0.1")  # All
    parser.add_argument("-p", "--port", type=int, metavar="port", help="Server port for TShark filter", default=443)  # All
    parser.add_argument("-k", "--keyfile", type=str, metavar="keyfile", help="Server private key", default="server-key.pem")  # All
    parser.add_argument("-f", "--pcap-file", type=str, metavar="pcapfile", help="PCAP file for \"cron\" mode")  # Cron
    parser.add_argument("--debug", action="store_true", help="loglevel=DEBUG", default=False) # All
    parsed_args = parser.parse_args()

    if parsed_args.mode == "daemon":
        import daemonize
        daemon = daemonize.Daemonize("ocacc", "/run/ocacc.pid",
                                     action=default_process,
                                     verbose=parsed_args.debug,
                                     privileged_action=lambda: parsed_args)
    elif parsed_args.mode == "cron":
        cron_process(parsed_args)
    else:
        default_process(parsed_args)
