FROM python:3.12-slim

RUN mkdir -p /app/logs

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY security.py audit_log.py ai_agent.py seo_report.py bot.py ./

CMD ["python", "bot.py"]
