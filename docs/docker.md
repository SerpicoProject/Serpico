# Running Inside Docker

The included `Dockerfile` allows to run Serpico inside docker from any system
that supports containers.

By default, Serpico listens on 8443, you can expose it as `443` if you would
like by using `docker run -p 443:8443 ...`

The image needs to first be built.

1. Build the image
2. Map the database location in docker-compose or at `docker run` time.
3. If the database doesn't exist, it will be created with defaults

## Creating the image

This will create a container with the current state of your repository.
The database is not created at this point, and this image is safe for
distribution.

```
docker build -t serpico .
```

The Dockerfile exposes a `VOLUME` at `/Serpico/db` to allow mounting an
external database through `docker-compose` or `docker run -v`.


## Running with `docker run`

```
# In the foreground
docker run --rm -p 8443 -v"$(pwd)":/Serpico/db -it serpico
```

This will store the database locally at `$PWD/master.db` Please note that the
path to the database on the host [must be absolute][1].

[1]: https://docs.docker.com/engine/reference/run/#volume-shared-filesystems

## Caveats

This is a work in progress, so a few things are currently not supported.

- Running a new container with an existing `master.db` will not work because
  `first_time.rb` will not run, and there won't be any certificates for SSL.
- `config.json` is not exposed to the host so customization requires rebuilding
  the image or accessing it with `docker exec bash`.

