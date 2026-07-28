# Local test secret directory

This directory exists so the complete configuration can demonstrate a contained
`secret_roots` boundary. Keep real secret files untracked. The runnable examples use the
`WEBHOOK_TEST_SECRET` environment reference and do not read a file from this directory.
