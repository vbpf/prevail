FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt update
RUN apt -yq --no-install-suggests --no-install-recommends install build-essential cmake \
    libboost-dev libboost-filesystem-dev libboost-program-options-dev libyaml-cpp-dev git \
    ca-certificates
WORKDIR /prevail
COPY . /prevail/
RUN mkdir build
WORKDIR /prevail/build
RUN cmake .. -DCMAKE_BUILD_TYPE=Release
RUN make -j $(nproc)
WORKDIR /prevail
ENTRYPOINT ["bin/check"]
