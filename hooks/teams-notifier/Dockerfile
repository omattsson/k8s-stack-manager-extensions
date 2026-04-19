FROM python:3.11-slim
WORKDIR /app
COPY server.py .
RUN pip install requests
USER nobody
EXPOSE 8080
CMD ["python3", "server.py"]
