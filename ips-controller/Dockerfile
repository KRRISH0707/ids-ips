FROM python:3.12-slim

WORKDIR /app

# Install iptables for real enforcement (not used in simulation mode)
RUN apt-get update && apt-get install -y --no-install-recommends iptables \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY controller.py .

CMD ["python", "-u", "controller.py"]
