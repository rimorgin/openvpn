FROM alpine:3.21

ADD ./setup.sh /setup.sh
COPY ./dependencies.json /tmp/dependencies.json

# Install dependencies
RUN apk add --no-cache --virtual=build-dependencies jq && \
  jq -r 'to_entries | .[] | .key + "=" + .value' /tmp/dependencies.json | xargs apk add --no-cache && \
  apk del --purge build-dependencies

WORKDIR /data

VOLUME ["/data"]

CMD ["/setup.sh"]
