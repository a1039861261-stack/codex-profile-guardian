# Codex state migration fixtures

The two SQL files are unmodified public migration sources from OpenAI Codex,
commit `6af345407d9c2a568da9d01b6c4b81a9e61495c0`:

- https://github.com/openai/codex/blob/6af345407d9c2a568da9d01b6c4b81a9e61495c0/codex-rs/state/migrations/0025_thread_timestamps_millis.sql
- https://github.com/openai/codex/blob/6af345407d9c2a568da9d01b6c4b81a9e61495c0/codex-rs/state/migrations/0039_threads_recency_at.sql

Copyright 2025 OpenAI. Apache-2.0; the upstream license and attribution notice
are included here. These migrations run only against synthetic test databases.
They are not shipped as product migrations or applied to a user's database.

The compatibility test creates fixture columns, runs both complete migrations,
and checks that unrelated INSERT/timestamp triggers remain present while
archived/rollout_path updates, quarantine, backup, and rollback preserve all
other values. SQLite's authorizer rejects applicable trigger programs at
preparation, both during read-only EXPLAIN and actual update/rollback.

References:
- https://www.sqlite.org/c3ref/set_authorizer.html
- https://www.sqlite.org/lang_explain.html
- https://www.sqlite.org/lang_createtrigger.html
