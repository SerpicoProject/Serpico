FROM ruby:2.6.3
MAINTAINER Serpico

ENV SRP_ROOT /Serpico
WORKDIR $SRP_ROOT
COPY . $SRP_ROOT
COPY ./docker/docker.sh scripts/docker.sh
RUN bundle install

# Allow DB to be on a shared volume
VOLUME ["$SRP_ROOT/db", "$SRP_ROOT/templates", "$SRP_ROOT/attachments", "$SRP_ROOT/tmp"]
EXPOSE 8443

CMD bash scripts/docker.sh
