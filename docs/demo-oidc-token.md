
# OIDC

You can visit mock-idp.dev to mint your own OIDC token for testing purposes. You have to update the configuration for Portcullis-Gate and Portcullis-Keep to trust that issuer, which
will soon be set up in the docker example.

@TODO: set up demo keep.yaml and gate.yaml to trust mock-idp.dev



```json
{
  "sub": "demo@paclabs.net",
  "email": "demo@paclabs.net",
  "groups": [
    "developer"
  ],
  "aud": [
    "portcullis-mcp"
  ],
  "name": "Joe Demo",
  "iss": "https://mock-idp.dev",
  "iat": 1774365130,
  "exp": 2089725130
}
```

# token

```
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Im1vY2staWRwLWtleS0xIn0.eyJhdWQiOlsicG9ydGN1bGxpcy1tY3AiXSwiZW1haWwiOiJkZW1vQHBhY2xhYnMubmV0IiwiZXhwIjoyMDg5NzI1MTgyLCJncm91cHMiOlsiZGV2ZWxvcGVyIl0sImlhdCI6MTc3NDM2NTE4MiwiaXNzIjoiaHR0cHM6Ly9tb2NrLWlkcC5kZXYiLCJuYW1lIjoiSm9lIERlbW8iLCJzdWIiOiJkZW1vQHBhY2xhYnMubmV0In0.cYm8pXjzsprhp5MmUoY20KIjh5ERlnKdiEdBBS4qYYq39_DuvTEMHoLch0Y-SoOEpU1a4b6Y203rSLvoTihGtxj-vD7qjGlPRSLA8rDGd5xmHCIuddfPoeHasdxed5jmM01h5IO9HbRttxOtUQ9-ghJOOiO08R8XdPtVRB6GVHR2JHPDjbiTBi6HmkdwyC7WM-ISbr8qTYnfOxgW93SfuCSYS7QPEFL2kiiFmoMXZH4Ua0cYJe10vm4wZxQjnQXzGG0DnLhx62vmTEXYLIpyQ8j0XW5TXn3H1HFeh0Wx7XCj25if5tSWCdq0chC_4P2YuLwO45UgVqkAduU_Ns8TwQ
```
