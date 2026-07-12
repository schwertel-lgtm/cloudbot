FROM python:3.12-slim-bookworm

RUN mkdir -p /app/logs

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY exec_security.py security.py audit_log.py claude_code_client.py docker_broker_client.py ai_agent.py seo_report.py bot.py ./

CMD ["python", "bot.py"]
