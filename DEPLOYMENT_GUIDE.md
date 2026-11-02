# Deployment

Use README local instructions. Compose files are provided as an unverified development convenience: `docker compose up --build`. They bind published ports to localhost. The web container forwards only `/api/v1/overview` to the API container via the runtime `API_INTERNAL_URL`. This setup is not production ready, has no authentication or database, and has not been tested in Docker. Production infrastructure, TLS, secrets, monitoring and secure service communication remain to be designed and verified.

See README for migration and disposable PostgreSQL test instructions. Migration downgrade removes data. Compose remains unverified; it does not automatically run migrations or provide a database.
