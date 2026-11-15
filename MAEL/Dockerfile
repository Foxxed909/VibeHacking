FROM python:3.12-alpine
WORKDIR /srv/novachat
COPY testapp/ /srv/novachat/
EXPOSE 3456
CMD ["python", "app.py", "--host", "0.0.0.0", "--port", "3456"]
