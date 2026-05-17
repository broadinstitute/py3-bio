FROM python:3.13

LABEL maintainer "Daniel Park <dpark@broadinstitute.org>"

WORKDIR /

RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /

RUN pip3 install --upgrade pip && pip3 install -r /requirements.txt

COPY . /

CMD ["/bin/bash"]
