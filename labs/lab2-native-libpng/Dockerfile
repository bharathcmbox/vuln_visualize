# Build environment for the libpng sanitizer-as-judge lab.
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
      clang llvm make zlib1g-dev ca-certificates libclang-rt-18-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /work
COPY build_and_check.sh /usr/local/bin/build_and_check.sh
RUN chmod +x /usr/local/bin/build_and_check.sh
ENTRYPOINT ["/usr/local/bin/build_and_check.sh"]
