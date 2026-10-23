-- Dev-only: least-privilege role used by the API and workers (RLS applies to it).
CREATE ROLE sentinel_app LOGIN PASSWORD 'sentinel_app' NOSUPERUSER NOBYPASSRLS;
GRANT CONNECT ON DATABASE sentinel TO sentinel_app;
