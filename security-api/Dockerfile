FROM ghcr.io/egikov99/deu-sec-lab:latest

WORKDIR /app

COPY security-api/requirements.txt /app/requirements.txt
RUN pip3 install --break-system-packages -r /app/requirements.txt

COPY security-api/main.py /app/main.py

EXPOSE 8088

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8088"]