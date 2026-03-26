FROM gcr.io/oss-fuzz-base/base-builder-python

RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        python3-dev && \
    rm -rf /var/lib/apt/lists/*

# Clone the upstream repository; OSS-Fuzz builds always pull from VCS
RUN git clone --depth 1 https://github.com/0ai-Cyberviser/Hancock $SRC/hancock

COPY build.sh $SRC/
