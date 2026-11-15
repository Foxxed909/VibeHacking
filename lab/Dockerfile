FROM python:3.12-slim
WORKDIR /workspace
COPY testapp/ /workspace/testapp/
RUN chown -R 65532:65532 /workspace/testapp
USER 65532:65532
EXPOSE 3456
CMD ["python", "-u", "testapp/app.py", "--host", "0.0.0.0", "--port", "3456"]

