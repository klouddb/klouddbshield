#!/usr/bin/bash
# set -e

# Array of logline prefixes
# PREFIXES=('m=%m u=%u d=%d l=%l e=%e x=%x c=%c b=%b v=%v p=%p h=%h a=[%a] r=%r ')

############################ widely used prefixes #################################
# PREFIXES=('%t %h %u %m ' '%m (%h:%u) ' '%m from %h by %u ' '%m in %d by %u@%h ' '%t %h %u [%p] ' '%m (%h:%u:%p) ' '%m from %h by %u pid=%p ' '%m in %d by %u@%h pid=%p ' '%t %h %u db=%d %m ' '%m in %d by %u@%h db=%d')
####################################################################################
PREFIXES=('[%p]: %t - %q[db=%d, user=%u, app=%a]  - [trx_id=%x] ')

FILE_SIZE=12MB # to modify file size

sudo rm -rf pglog
sudo mkdir pglog
sudo chmod -R 777 pglog

export FILE_SIZE

# Iterate over the array
for INDEX in "${!PREFIXES[@]}"; do
    PREFIX="${PREFIXES[$INDEX]}"

    sudo mkdir pglog/log$INDEX
    sudo chmod -R 777 pglog/log$INDEX

    echo "Running with prefix: $PREFIX"

    integrationtest setup --prefix "$PREFIX" --size "$FILE_SIZE" --index $INDEX
    echo "$PREFIX is done"
    sudo chmod -R 777 pglog/log$INDEX

    echo "running logparser on $PREFIX"

    ## test with prefix in arg
    integrationtest test -p "$PREFIX" -f "pglog/log$INDEX/postgresql*.log"

    echo "stopping docker-compose with prefix: $PREFIX"
    # Stop the postgres service and claim all volumes related to that service
    docker-compose down -v
done


# Set permissions for pglog directory
sudo chmod 777 pglog/*