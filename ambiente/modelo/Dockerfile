FROM alpine:latest AS preparo
RUN echo "citizen-tech-market" > /tmp/versao.txt

FROM python:3.7-slim-buster
MAINTAINER devops@citizen.tech
ENV API_TOKEN=@@G14@@
ENV PORTA=@@PORTA@@
WORKDIR app
ADD . /app
COPY --from=preparo /tmp/versao.txt /app/versao.txt
RUN cd /app && pip install -r requirements.txt
RUN sudo chmod -R 777 /app || chmod -R 777 /app
EXPOSE 22 @@PORTA@@
USER root
CMD ["python", "-m", "http.server"]
CMD ["python", "app.py"]
