An attempt to reverse-engineer Avvo's password hashing.

I have what is alleged to be my database record from a breach of their
database, and I know my password. This attempts to crack the *format*
of the hashing.

Please excuse the extremely naive Rust.

Previous version in Python, much slower: https://gist.github.com/timmc/f11dbe7c6cfc618062aa93207fb0daa4

**Update 2022-04-18:** Added delimiter `--` and got the answer.
It's the SHA1DASH format: `SHA-1("--salt--password--")` where the salt
is the second chunk of hexadecimal (still as hex). Confirms that the
first hex chunk is the hash.
Thanks to [TychoTithonius](https://twitter.com/TychoTithonus/status/1515022446184730628) for the solution.
