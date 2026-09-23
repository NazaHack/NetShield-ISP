# Test fixtures

`nmap_real_scan.xml` is genuine output from Nmap 7.93, captured by scanning the
project's own PostgreSQL and Redis containers with the exact command the scanning
engine builds. It is kept verbatim, including the `<!DOCTYPE>` declaration and the
`<hosthint>` elements, so that the parser is exercised against what Nmap really
emits rather than against a tidied-up approximation.
