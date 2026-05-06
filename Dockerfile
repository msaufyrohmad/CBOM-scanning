FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip \
        binutils libc-bin procps \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir psutil

WORKDIR /app
COPY 1BinariesUsed-docker.py /app/1BinariesUsed-docker.py

# Output path (bind-mount /out at runtime)
ENV OUTPUT_CSV=/out/binaries_used.csv
ENV VERBOSE=1
VOLUME ["/out"]

CMD ["python3", "/app/1BinariesUsed-docker.py"]
