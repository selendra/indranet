# This is the build stage for indranet. Here we create the binary in a temporary image.
FROM docker.io/paritytech/ci-linux:production as builder

WORKDIR /indranet
COPY . /indranet

RUN cargo build --locked --release

# This is the 2nd stage: a very small image where we copy the indranet binary."
FROM docker.io/library/ubuntu:20.04

LABEL description="Multistage Docker image for indranet: a platform for web3" \
	io.parity.image.type="builder" \
	io.parity.image.authors="info@selendra.org" \
	io.parity.image.vendor="indranet" \
	io.parity.image.description="indranet: a platform for web3" \
	io.parity.image.source="https://github.com/selendra/indranet/blob/${VCS_REF}/scripts/dockerfiles/indranet/indranet_builder.Dockerfile" \
	io.parity.image.documentation="https://github.com/selendra/indranet/"

COPY --from=builder /indranet/target/release/indranet /usr/local/bin

RUN useradd -m -u 1000 -U -s /bin/sh -d /indranet indranet && \
	mkdir -p /data /indranet/.local/share && \
	chown -R indranet:indranet /data && \
	ln -s /data /indranet/.local/share/indranet && \
# unclutter and minimize the attack surface
	rm -rf /usr/bin /usr/sbin && \
# check if executable works in this container
	/usr/local/bin/indranet --version

USER indranet

EXPOSE 30333 9933 9944 9615
VOLUME ["/data"]

ENTRYPOINT ["/usr/local/bin/indranet"]
