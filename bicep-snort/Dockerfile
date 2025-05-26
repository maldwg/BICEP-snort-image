ARG BASE_IMAGE
ARG VERSION
FROM ${BASE_IMAGE}:${VERSION}

RUN apt install python3-pip -y

RUN mkdir /opt/code
WORKDIR /opt/code

COPY ./requirements.txt /opt/code/requirements.txt
COPY ./src/ /opt/code/src
COPY ./apt-requirements.txt /tmp/apt-requirements.txt
COPY ./snort.lua /etc/snort/etc/snort/snort.lua
ENV SNORT_DEFAULT_CONFIG_LOCATION=/etc/snort/etc/snort/snort.lua

RUN pip3 install -r requirements.txt
RUN xargs apt install -y < /tmp/apt-requirements.txt


# path to locate the IDSBase implementation
ENV IDS_MODULE=src.models.snort
ENV IDS_CLASS=Snort
# Define default value for configuration directory. 
# gets overriden in the configuration process of Snort
ENV SNORT_CONFIG_DIR=/tmp/configuration/
CMD [ "/bin/bash","-c","fastapi dev /opt/code/src/main.py --host 0.0.0.0 --port ${PORT}" ]