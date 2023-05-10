FROM --platform linux/amd64 python:3.8-alpine 

RUN apk add --no-cache skopeo
# Create app directory
RUN mkdir -p /skopeo/app
WORKDIR /skopeo/app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY server.py server.py
ENV FLASK_APP=server
CMD [ "python",  "-u","./server.py" ]