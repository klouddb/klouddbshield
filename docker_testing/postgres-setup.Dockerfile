FROM postgres:latest

ENV POSTGRES_USER myuser
ENV POSTGRES_PASSWORD password


# Copy the entrypoint script
COPY entrypoint.sh /docker-entrypoint-initdb.d/entrypoint.sh
RUN chmod +x /docker-entrypoint-initdb.d/entrypoint.sh

# # Copy the SQL script for user creation
# COPY init-users.sql /docker-entrypoint-initdb.d/init-users.sql
# RUN chmod +x /docker-entrypoint-initdb.d/init-users.sql



EXPOSE 5432
