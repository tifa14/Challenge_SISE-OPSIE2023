FROM python:3.8-slim-buster

WORKDIR /app

COPY requirements.txt .

RUN pip3 install --no-cache-dir -r requirements.txt

COPY firewall.log .
COPY . .

EXPOSE 8501

CMD ["streamlit", "run", "app.py"]
