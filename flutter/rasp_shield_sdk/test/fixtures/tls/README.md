Test-only TLS material for `test/tls_pinning_dio_test.dart`: a throwaway CA
certificate (its key was deleted after signing) and a `localhost` server
certificate and key signed by it. Nothing here is trusted outside the test.
