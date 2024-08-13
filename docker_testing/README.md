## README

### Introduction

This project includes tools and commands to generate test data for PII scanner and run automated integration tests for log parsers. It provides a streamlined process to install dependencies, generate PII data, and execute migrations.

### Installation

To install the necessary tools, navigate to the root directory of the repository and run:

```sh
make install
```

This command will install `ciscollection` and `integrationtest`.

### Generating Test Data

The `integrationtest` command is used to run automated integration tests for the log parser. It includes a `generate-data` subcommand to generate data with PII information.

#### Steps to Generate Data:

1. Run the `generate-data` command to create data for 10 different tables with PII information. Each table will have 1000 rows.
2. The command will execute migration commands for all SQL files available in the `./migrations` directory.
3. It will load the `kshieldconfig.toml` configuration file to connect to the database and apply the migrations.

#### Example Command:

```sh
integrationtest generate-data --migration-path docker_testing/migrations
```

This command will:
- Use the `--migration-path` flag to specify the path of migration files. The default value for this flag is `./migration`.
- Connect to the database using the configuration from `kshieldconfig.toml`.
- Run all SQL files in the specified migration path on the connected database.

### Generating Random Data

To generate random data, we are using the [Mockaroo](https://mockaroo.com/) website. Mockaroo can generate SQL files with dummy data based on a given input structure, which is useful for creating realistic test data for development and testing purposes.

### Directory Structure

- `./migrations`: Directory containing SQL migration files. These files are executed to set up the database schema and insert test data.
- `docker_testing/migrations`: Alternative directory for migration files. This can be specified using the `--migration-path` flag.

### Running Migration Files

To run any other migration file, use the `--migration-path` flag to pass the path of the migration files. For example:

```sh
integrationtest generate-data --migration-path path/to/your/migrations
```

### Execution

To execute the installation and data generation, follow these steps:

1. From the root of the repository, install the dependencies:

    ```sh
    make install
    ```

2. Generate the test data with PII information:

    ```sh
    integrationtest generate-data --migration-path docker_testing/migrations
    ```
