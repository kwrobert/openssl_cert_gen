# Use an official Python runtime as a parent image
FROM ubuntu:bionic

# Set the working directory to /app
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY cert_gen.py /app

# Install any needed packages specified in requirements.txt
RUN apt update && apt install -y openssl python3.7 python3-pip
RUN pip3 install bullet inquirer

# Make ssh port 22 available to the world outside this container
EXPOSE 22

# Define environment variable
# ENV NAME World

# Run app.py when the container launches
CMD ["python3", "cert_gen.py"]
