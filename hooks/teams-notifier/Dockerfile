FROM python:3.12-alpine
WORKDIR /app
COPY server.py .
EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["python3", "server.py"]
