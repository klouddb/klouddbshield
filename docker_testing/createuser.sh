PGPASSWORD=password psql -U myuser -h postgres -p 5432 -d postgres -c "CREATE USER user0 WITH PASSWORD 'password';"
PGPASSWORD=password psql -U myuser -h postgres -p 5432 -d postgres -c "CREATE USER user1 WITH PASSWORD 'password';"
PGPASSWORD=password psql -U myuser -h postgres -p 5432 -d postgres -c "CREATE USER user2 WITH PASSWORD 'password';"
PGPASSWORD=password psql -U myuser -h postgres -p 5432 -d postgres -c "CREATE USER user3 WITH PASSWORD 'password';"
PGPASSWORD=password psql -U myuser -h postgres -p 5432 -d postgres -c "CREATE USER user4 WITH PASSWORD 'password';"
PGPASSWORD=password psql -U myuser -h postgres -p 5432 -d postgres -c "CREATE USER user5 WITH PASSWORD 'password';"

PGPASSWORD=password psql -U myuser -h postgres -p 5432 -d postgres -c "ALTER ROLE user0 WITH SUPERUSER;"
PGPASSWORD=password psql -U myuser -h postgres -p 5432 -d postgres -c "ALTER ROLE user1 WITH SUPERUSER;"
PGPASSWORD=password psql -U myuser -h postgres -p 5432 -d postgres -c "ALTER ROLE user2 WITH SUPERUSER;"
PGPASSWORD=password psql -U myuser -h postgres -p 5432 -d postgres -c "ALTER ROLE user3 WITH SUPERUSER;"
PGPASSWORD=password psql -U myuser -h postgres -p 5432 -d postgres -c "ALTER ROLE user4 WITH SUPERUSER;"
PGPASSWORD=password psql -U myuser -h postgres -p 5432 -d postgres -c "ALTER ROLE user5 WITH SUPERUSER;"


PGPASSWORD=password pgbench -i -s 100 -U myuser -h postgres -p 5432 -d postgres