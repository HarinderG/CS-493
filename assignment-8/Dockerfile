FROM python:3.8
WORKDIR /usr/src/app
COPY requirements.txt ./
RUN pip install -r requirements.txt
COPY . .
ENV PORT=8000
EXPOSE ${PORT}
ENV GOOGLE_APPLICATION_CREDENTIALS="my-key.json"
CMD [ "python3", "main.py" ]
