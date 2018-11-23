#!/usr/bin/bash
# This script is used as the entry point for the docker image.
# It will initialize the database if it isn't already present.

if [ ! -f "$SRP_ROOT/db/master.db" ]; then
    echo "First run detected. Initializing database..."
    ruby "$SRP_ROOT/scripts/first_time.rb"
fi

# CMD ["ruby", "serpico.rb"]
ruby serpico.rb

