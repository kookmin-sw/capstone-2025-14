FROM ubuntu:24.04

ENV TZ=Asia/Seoul
ENV PYTHONIOENCODING=UTF-8
ENV LC_CTYPE=C.UTF-8
ENV TERM=xterm-256color
ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y software-properties-common && \
    add-apt-repository ppa:deadsnakes/ppa && \
    apt-get update && apt-get install -y \
      python3.9 \
      python3.9-venv \
      python3-pip \
      build-essential \
      net-tools \
      gcc \
      gcc-12-plugin-dev \
      clang \
      llvm \
      wget \
      curl \
      git \
      vim \
      zsh \
      fonts-powerline \
      unzip \
      openssh-server && \
    apt-get clean

# SSH 관련 설정
RUN mkdir /var/run/sshd
RUN echo 'root:root' | chpasswd
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# oh-my-zsh 설치
ENV RUNZSH=no
ENV CHSH=no
RUN sh -c "$(wget -O- https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"

RUN chsh -s /usr/bin/zsh

RUN git clone https://github.com/caiogondim/bullet-train.zsh.git ~/.oh-my-zsh/custom/themes/bullet-train
ENV ZSH_THEME="bullet-train/bullet-train"

RUN echo 'export ZSH="$HOME/.oh-my-zsh"' > /root/.zshrc && \
    echo 'ZSH_THEME="bullet-train/bullet-train"' >> /root/.zshrc && \
    echo "plugins=(git)" >> /root/.zshrc && \
    echo "source \$ZSH/oh-my-zsh.sh" >> /root/.zshrc

# Hack 폰트 설치
RUN wget -O /tmp/Hack-v3.003-ttf.zip https://github.com/source-foundry/Hack/releases/download/v3.003/Hack-v3.003-ttf.zip && \
    mkdir -p /usr/share/fonts/truetype/hack && \
    unzip /tmp/Hack-v3.003-ttf.zip -d /usr/share/fonts/truetype/hack && \
    fc-cache -fv && \
    rm /tmp/Hack-v3.003-ttf.zip

# AFL++ 설치
RUN git clone https://github.com/AFLplusplus/AFLplusplus.git /opt/aflplusplus && \
    cd /opt/aflplusplus && \
    make distrib && \
    make install

WORKDIR /app

RUN mkdir project

# Django 프로젝트 셋업
RUN python3.9 -m venv venv
RUN ./venv/bin/pip install --upgrade pip && \
    ./venv/bin/pip install django && \
    ./venv/bin/django-admin startproject capstone project

# SSH 포트 열기
EXPOSE 22

# 컨테이너 시작 시 sshd와 zsh를 동시에 실행
CMD service ssh start && /usr/bin/zsh -l
