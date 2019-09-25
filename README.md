# JWT Authentication server Boilerplate

Sample JWT Authentication server for generating a JWT to use in the `Authentication` header by the built in JWT decoder in Hasura GraphQL Engine when started in JWT mode.

## Getting Started

### Build the docker image

```bash
    docker build -t socialalpha/auth .
```

### Add user schema manually to Hasura

Use the instructions <https://docs.hasura.io/1.0/graphql/manual/index.html> add a `users` table with the following fields using the console

| name       | type    | nullable | unique | default | primary |
| ---------- | ------- | -------- | ------ | ------- | ------- |
| id         | Integer | no       | yes    |         | yes     |
| email   | Text    | no       | yes    |         | no      |
| password   | Text    | no       | no     |         | no      |
| token      | Text    | no       | no     |         | no      |
| created_at | Date    | no       | no     | now()   |         |


### Deploy with Docker

- Replace /etc/hasura/docker-compose.yaml with example docker-compose.yaml in this folder (make a backup first!)
- Replace /etc/hasura/Caddyfile with example Caddyfile in this folder (make a backup first!)

## Usage

### Signup/Login

- Examples below assume you are running the curl commands from the host running hasura. If running remotely, replace http://localhost:8080 with IP/hostname of the server

Once deployed or started locally, we can create an user using `/signup` API like below:

```bash
curl -H "Content-Type: application/json" \
     -d'{"email": "hello@jaaga.in", "password": "test123", "confirmPassword": "test123"}' \
     http://localhost:8080/auth/signup
```

On success, we get the response:

```json
{
  "id": 1,
  "email": "hello@jaaga.in"
}
```

We can also use `/login` API to fetch the user token:

```bash
curl -H "Content-Type: application/json" \
     -d'{"email": "hello@jaaga.in", "password": "test123"}' \
     http://localhost:8080/auth/login
```

On success, we get the response:

```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEsIm5hbWUiOiJ0ZXN0MTIzIiwiaWF0IjoxNTQwMjkyMzgyLjQwOSwiaHR0cHM6Ly9oYXN1cmEuaW8vand0L2NsYWltcyI6eyJ4LWhhc3VyYS1hbGxvd2VkLXJvbGVzIjpbImVkaXRvciIsInVzZXIiLCJtb2QiXSwieC1oYXN1cmEtdXNlci1pZCI6MSwieC1oYXN1cmEtZGVmYXVsdC1yb2xlIjoidXNlciJ9fQ.KtAUroqyBroBJL7O9og3Z4JnRkWNfr07cHQfeLarclU"
}
```

### Authenticate JWT using GraphQL Engine

The GraphQL engine comes with built in JWT authentication.  You will need to start the engine with the same secret/key as the JWT auth server using the environment variable `HASURA_GRAPHQL_JWT_SECRET` (HASURA_GRAPHQL_ACCESS_KEY is also required see the docs)

In your GraphQL engine you will need to add permissions for a user named `user` with read permissions on the table and columns.

A sample CURL command using the above token would be:

```bash
curl -X POST \
  http://localhost:8081/v1alpha1/graphql \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwibmFtZSI6InRlc3QxMjMiLCJpYXQiOjE1NDAzNzY4MTUuODUzLCJodHRwczovL2hhc3VyYS5pby9qd3QvY2xhaW1zIjp7IngtaGFzdXJhLWFsbG93ZWQtcm9sZXMiOlsiZWRpdG9yIiwidXNlciIsIm1vZCJdLCJ4LWhhc3VyYS11c2VyLWlkIjoiMSIsIngtaGFzdXJhLWRlZmF1bHQtcm9sZSI6InVzZXIiLCJ4LWhhc3VyYS1yb2xlIjoidXNlciJ9fQ.w9uj0FtesZOFUnwYT2KOWHr6IKWsDRuOC9G2GakBgMI' \
  -H 'Content-Type: application/json' \
  -d '{ "query": "{ table { column } }" }'
```

See [the Hasura docs](https://docs.hasura.io/1.0/graphql/manual/auth/jwt.html) for more details
.
