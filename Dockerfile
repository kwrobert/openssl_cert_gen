# Use an official Python runtime as a parent image
FROM ubuntu:bionic

# Set the working directory to /app
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install openssl
apt install openssl

# Make port 80 available to the world outside this container
EXPOSE 22

# Define environment variable
# ENV NAME World

# Run app.py when the container launches
CMD ["bash", "test.sh"]
