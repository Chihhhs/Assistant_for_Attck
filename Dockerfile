FROM python

RUN apt update && apt install -y python3 python3-pip curl wget

COPY . /app
RUN chmod +x setup.sh
RUN ./setup.sh

WORKDIR /app

RUN pip3 install -r requirements.txt