FROM ruby:2.3.3
MAINTAINER Serpico

ENV SRP_ROOT /Serpico
WORKDIR $SRP_ROOT
COPY . $SRP_ROOT
COPY ./docker/docker.sh scripts/docker.sh
RUN bundle install

# Allow DB to be on a shared volume
VOLUME ["$SRP_ROOT/db"]
EXPOSE 8443

CMD ["bash", "scripts/docker.sh"]
