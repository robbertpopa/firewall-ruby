# MongoDB NoSQL Injection Protection

## What I changed

I added MongoDB runtime protection by patching `Mongo::Collection` methods and scanning their inputs before the query reaches the driver.

## Patched Mongo methods

The sink scans these `Mongo::Collection` calls:

- `find`
- `aggregate`
- `update_one`
- `update_many`
- `replace_one`
- `delete_one`
- `delete_many`
- `find_one_and_update`
- `find_one_and_replace`
- `find_one_and_delete`
- `insert_one`
- `insert_many`

The patch is passive: it only activates if the app already loaded `Mongo::Collection`.

## Scanner behavior

The scanner works with four payload contexts:

- `filter`
- `update`
- `pipeline`
- `document`

### What it blocks

- JavaScript-capable operators anywhere:
  - `$where`
  - `$function`
  - `$accumulator`
- High-risk field-level filter operators:
  - `$ne`
  - `$not`
- `$`-prefixed keys in document context (insert/replacement docs)

## Tests added

- Scanner unit tests:
  - `test/aikido/zen/scanners/nosql_injection_scanner_test.rb`
- Sink interception tests:
  - `test/aikido/zen/sinks/mongo_test.rb`

The tests cover safe queries, blocked malicious payloads, and patch interception on all supported methods.

## Tradeoffs

- Blocking `$ne` and `$not` is intentional for stronger default protection, but this may block some legitimate trusted queries.
