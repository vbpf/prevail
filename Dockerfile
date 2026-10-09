FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt update
RUN apt -yq --no-install-suggests --no-install-recommends install build-essential cmake \
    libboost-dev libboost-filesystem-dev libboost-program-options-dev libyaml-cpp-dev git \
    ca-certificates
WORKDIR /prevail
COPY . /prevail/
# Initialize plain clones; source archives and worktrees must already include dependencies.
RUN if [ -d .git ]; then git submodule update --init --recursive; fi
RUN mkdir build
WORKDIR /prevail/build
RUN cmake .. -DCMAKE_BUILD_TYPE=Release
RUN make -j $(nproc)
WORKDIR /prevail
ENTRYPOINT ["bin/prevail"]
