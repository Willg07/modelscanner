FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends strace \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir numpy \
    && pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu
COPY load_probe.py /opt/load_probe.py
USER 10001:10001
ENTRYPOINT ["python", "/opt/load_probe.py"]
