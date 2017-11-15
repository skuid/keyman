FROM debian

RUN apt-get update && apt-get install -y openssh-server sudo

ADD sshd_config /etc/ssh/sshd_config
ADD ca.pub /etc/ssh/ca.pub

EXPOSE 22

ENV SSH_USER core

RUN mkdir -p /run/sshd /etc/ssh/auth_principals \
    && sshd -t \
    && echo "$SSH_USER" > /etc/ssh/auth_principals/$SSH_USER \
    && echo "root" > /etc/ssh/auth_principals/root \
    && echo "SSHD_OPTS='-E /var/log/sshd.log'" > /etc/default/ssh \
    && useradd --create-home --shell /usr/bin/bash $SSH_USER -G sudo \
    && usermod -p '*' $SSH_USER \
    && echo "%sudo ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
    #&& adduser --disabled-password --shell /bin/bash core

ADD init.sh /init.sh

CMD ["/init.sh"]
