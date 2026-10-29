FROM python:3.12-slim
WORKDIR /app
RUN useradd --create-home soc
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY mini_soc ./mini_soc
COPY data ./data
COPY eksempler ./eksempler
COPY eval ./eval
USER soc
ENV SOC_VERT=0.0.0.0 SOC_PORT=8000
EXPOSE 8000
CMD ["python", "-m", "mini_soc", "server", "eksempler"]
