FROM python:3.13

LABEL maintainer "Daniel Park <dpark@broadinstitute.org>"

WORKDIR /

RUN apt-get update && apt-get upgrade -y openssl libssl-dev libssl3t64 openssl-provider-legacy libssh2-1-dev libssh2-1t64 imagemagick imagemagick-7-common imagemagick-7.q16 libmagickcore-7-arch-config libmagickcore-7-headers libmagickcore-7.q16-10 libmagickcore-7.q16-10-extra libmagickcore-7.q16-dev libmagickcore-dev libmagickwand-7-headers libmagickwand-7.q16-10 libmagickwand-7.q16-dev libmagickwand-dev && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /

RUN pip3 install --upgrade pip && pip3 install -r /requirements.txt

COPY . /

CMD ["/bin/bash"]
