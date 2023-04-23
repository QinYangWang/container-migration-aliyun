FROM alpine:latest

RUN apk add --no-cache skopeo python3-dev python3 py3-pip

# Tell docker that all future commands should run as the appuser user
USER root

# Create app directory
RUN mkdir -p /skopeo/app
WORKDIR /skopeo/app

RUN pip install --upgrade pip
RUN pip install cryptography flask aliyun-python-sdk-core -i https://mirrors.aliyun.com/pypi/simple/

# Bundle app source
COPY server.py server.py

EXPOSE 9000
ENV FLASK_APP=server
ENTRYPOINT ["python3", "-u",  "server.py"]