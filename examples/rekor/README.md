# Rekor Transparency Log Client

The following examples all interface with the Rekor Transparency Log Client.

## create_log_entry

```bash
cargo run --example create_log_entry -- \
     --hash c7ead87fa5c82d2b17feece1c2ee1bda8e94788f4b208de5057b3617a42b7413\
     --url https://raw.githubusercontent.com/jyotsna-penumaka/rekor-rs/rekor-functionality/test_data/data\
     --public_key LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFeEhUTWRSQk80ZThCcGZ3cG5KMlozT2JMRlVrVQpaUVp6WGxtKzdyd1lZKzhSMUZpRWhmS0JZclZraGpHL2lCUjZac2s3Z01iYWZPOG9FM01lUEVvWU93PT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==\
     --signature MEUCIHWACbBnw+YkJCy2tVQd5i7VH6HgkdVBdP7HRV1IEsDuAiEA19iJNvmkE6We7iZGjHsTkjXV8QhK9iXu0ArUxvJF1N8=\
     --key_format x509\
     --api_version 0.0.1
```

