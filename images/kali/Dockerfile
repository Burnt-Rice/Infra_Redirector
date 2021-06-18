FROM kalilinux/kali-rolling:latest


RUN set -x \ 
    && echo '[+]Updating Kali' \
    && DEBIAN_FRONTEND='noninteractive' apt update -qy  \
    && echo '[+] Done'

RUN set -x \ 
    && echo '[+]Installing Tools' \
    && DEBIAN_FRONTEND='noninteractive' apt install kali-tools-top10 -qy \
    openssh-server \
    tmux \
    dirbuster \
    gobuster \
    python3-pip \
    && echo '[+] Done'
RUN set -x \ 
    && echo '[+]Installing python3 linters' \
    && pip3 install mypy \
    && pip3 install black \
    && echo '[+] Done'

CMD ["/bin/bash"]
