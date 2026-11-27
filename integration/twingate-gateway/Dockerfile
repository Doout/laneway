FROM python:3.13-alpine
RUN apk add --no-cache iproute2
COPY --chmod=755 fixture.py /usr/local/bin/laneway
ENTRYPOINT ["/usr/local/bin/laneway"]
