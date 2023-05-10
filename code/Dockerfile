FROM --platform=linux/amd64 python:alpine 

RUN apk add --no-cache skopeo
# Create app directory
RUN mkdir -p /skopeo/app
WORKDIR /skopeo/app
RUN pip install cryptography flask aliyun-python-sdk-core -i https://mirrors.aliyun.com/pypi/simple/ -t .
COPY server.py server.py
ENV FLASK_APP=server
CMD [ "python",  "-u","./server.py" ]