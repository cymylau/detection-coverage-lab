# Build and start
docker-compose up -d

# Enter the container
docker-compose exec edr-tester /bin/bash

# Or run interactively
docker-compose run --rm edr-tester bash
