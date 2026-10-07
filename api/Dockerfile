FROM python:3.12-alpine

# `wg` is needed only for key generation and `wg syncconf` of the shared wg0.
RUN apk add --no-cache wireguard-tools-wg

WORKDIR /app
COPY gateway_api.py /app/gateway_api.py
COPY static/ /app/static/

ENTRYPOINT ["python3", "-u", "/app/gateway_api.py"]
CMD ["serve"]
