FROM python

RUN apt update && apt install -y python3 python3-pip curl wget

RUN chmod +x setup.sh
RUN ./setup.sh

WORKDIR /app

COPY requirements.txt /app/requirements.txt

RUN pip3 install -r requirements.txt