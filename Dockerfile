# Use the official Python base image with version 3.8.10
FROM python:3.8.10

# Set the working directory inside the container
WORKDIR /app

# Copy the requirements.txt file to the working directory
COPY requirements.txt .

# Install the Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the app.py file to the working directory
COPY app.py .

# Expose port 5000 for the Flask app
EXPOSE 5000

# Set the entrypoint command to run the Flask app
CMD ["python", "app.py"]