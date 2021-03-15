FROM python:3.7

LABEL maintainer "Daniel Park <dpark@broadinstitute.org>"

WORKDIR /

COPY requirements.txt /

RUN pip3 install -r /requirements.txt

COPY . /

CMD ["/bin/bash"]
