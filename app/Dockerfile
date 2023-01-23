FROM python:3.10-slim

WORKDIR /var/www
COPY src src
COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

ENV FLASK_APP src/app.py
ENV FLASK_RUN_PORT 8000
ENV FLASK_RUN_HOST 0.0.0.0

EXPOSE 8000

CMD ["python", "-m", "flask", "run"]