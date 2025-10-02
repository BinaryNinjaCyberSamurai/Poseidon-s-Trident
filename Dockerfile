# Use an official Python runtime as a parent image
FROM python:3.8-slim

# Set the working directory in the container to /app
WORKDIR /app

# Copy only necessary files (using .dockerignore)
COPY . /app

# Install dependencies from requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Separate build and runtime stages for efficiency
# Build stage
FROM python:3.8-slim AS builder
WORKDIR /build
COPY . .
RUN pip install --no-cache-dir -r requirements.txt

# Runtime stage
FROM python:3.8-slim
WORKDIR /app
COPY --from=builder /build /app

# Expose port 80
EXPOSE 80

# Run your cybersecurity software
CMD ["python", "PoseidonsTrident_Cybersecurity.py"]

# Builder stage
FROM python:3.11-slim AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --user -r requirements.txt

# Runtime stage
FROM python:3.11-slim
WORKDIR /app
COPY --from=builder /root/.local /root/.local
COPY . .
ENV PATH=/root/.local/bin:$PATH
CMD ["python", "main.py"]