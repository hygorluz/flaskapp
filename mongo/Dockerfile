########################################################
# Dockerfile for: MONGODB DATABASE
########################################################
# How to run
#  - docker-compose up -d georanker_mongo
# How to build
#  - docker-compose build --no-cache
########################################################
# SERVICES AND LIBS INSTALLED:
# - MongoDB server 4.0.6
########################################################
# This dockerfile was created based on:
# - https://github.com/Khezen/docker-mongo
# - https://hub.docker.com/r/khezen/mongo/
########################################################
# Every time this machine starts, it can, if does not exists
# restore a dump with the initial state so the collections
# are created automaticaly on the first run.
########################################################

FROM mongo:4.0.6

MAINTAINER Hygor Luz <hygor.c.luz@gmail.com>

COPY ./mongodump/current.tar.gz /data/dump/

# Create the execution binary for the entrypoint
RUN echo "#\!/bin/sh\n if [ ! -f /data/db/storage.bson ]; then \n tar -zxvf /data/dump/current.tar.gz -C /data/db/ \n fi \n mongod --smallfiles --bind_ip_all" > /run/startup.sh \
    && chmod a+x /run/startup.sh

EXPOSE 27017

VOLUME ["/data/db/"]

CMD ["/bin/sh", "-c", "/run/startup.sh"]

ENTRYPOINT ["/bin/sh", "-c", "/run/startup.sh"]