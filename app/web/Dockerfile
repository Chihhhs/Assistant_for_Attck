FROM ubuntu:22.04

RUN apt update && apt install -y python3 python3-pip curl wget

ADD --chmod=755 https://astral.sh/uv/install.sh /install.sh
RUN /install.sh && rm /install.sh

WORKDIR /app

COPY . /app

RUN /root/.cargo/bin/uv pip install --system --no-cache -r requirements.txt

EXPOSE 8501

CMD ["python3", "-m", "streamlit", "run", "Home.py"]