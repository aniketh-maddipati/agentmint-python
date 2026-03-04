FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -e . fastmcp
EXPOSE 8000
CMD ["python", "-m", "mcp_server.server"]
