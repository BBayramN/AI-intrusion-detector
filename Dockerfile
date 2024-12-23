# Use Python 3.10 slim as our base
FROM python:3.10-slim

# Update and install tshark
RUN apt-get update && apt-get install -y \
    tshark \
    && apt-get clean

# Set the working directory for the Django project
WORKDIR /app

# Copy Django requirements (for your main Django app)
COPY requirements.txt /app/ 
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your Django application code into /app
COPY . /app/
COPY . /app/NTLFlowLyzer
# (Optional) Expose port 8000 if you want external traffic
EXPOSE 8000

# Now install NTLFlowLyzer. 
# 1) If NTLFlowLyzer is part of the same repo, and is located in /app/NTLFlowLyzer
# 2) If NTLFlowLyzer has its own requirements, copy them or reference them.
#RUN git clone https://github.com/ahlashkari/NTLFlowLyzer.git
# WORKDIR /app/NTLFlowLyzer
# If NTLFlowLyzer has a separate requirements.txt
# RUN pip install --no-cache-dir -r requirements.txt

# Finally, install NTLFlowLyzer via setup.py
# RUN python3 setup.py install

# Return to /app (the Django project root) for final CMD
WORKDIR /app

# Start Gunicorn for the Django app
CMD ["gunicorn", "ai_intrusion_detector.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "2", "--threads", "4"]
