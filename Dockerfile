FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY luau_filter.hpp httplib.h server.cpp ./
RUN clang++ -std=c++20 -O3 -pthread server.cpp -o bytecode_server

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=build /app/bytecode_server /app/bytecode_server
EXPOSE 10000
CMD ["/app/bytecode_server"]