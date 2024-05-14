FROM ubuntu:22.04

RUN apt update && apt install -y python3 python3-pip curl wget

WORKDIR /app

COPY . /app

RUN pip3 install -r requirements.txt

EXPOSE 8501

CMD ["python3", "-m", "streamlit", "run", "Home.py"]