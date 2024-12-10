# Base image
FROM python:3.10-slim

# Install dependencies
RUN apt-get update && apt-get install -y \
    tshark \
    && apt-get clean

# Set the working directory
WORKDIR /app

# Copy the requirements file
COPY requirements.txt /app/

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . /app/


# Expose the port and run the app
CMD ["gunicorn", "ai_intrusion_detector.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "2", "--threads", "4"]

