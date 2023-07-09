# Example HMAC using modified version of Rocket.rs

## Usage

Install HTTPIE + HMAC Plugin:

```
python3 -m pip install httpie httpie-hmac
```

Run project:

```
cargo run
```

Use custom.py formatter (file.json is larger than a single peek buffer):

```
HTTPIE_HMAC_SECRET=`cat ./keys/server.key` HTTPIE_HMAC_PUBLIC_KEY=`cat ./keys/server.crt` http --auth-type=hmac --auth="format:custom.py"  POST localhost:8000/some/path/421 < ../file.json
```

Can also set HTTPIE_HMAC_PUBLIC_KEY to use ./keys/bad_server.crt (incorrectly signed public key) or server_2.crt (correctly signed, but wrong public key - set HTTPIE_HMAC_SECRET to use ./keys/server_2.crt for correct pair).