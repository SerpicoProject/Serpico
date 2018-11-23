FROM ruby:2.3.5
MAINTAINER Serpico
ENV SRP_ROOT /Serpico
WORKDIR $SRP_ROOT
# No volume: It will be mounted by docker-compose.
COPY Gemfile $SRP_ROOT/
RUN bundle install
EXPOSE 8443
CMD ["bash", "docker/docker.sh"]
