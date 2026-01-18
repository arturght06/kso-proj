# 1. CA (Certificate Authority)
openssl req -x509 -newkey rsa:2048 -days 3650 -nodes -keyout ca-key.pem -out ca.pem -subj "/CN=KSO-CA"

# 2. Certyfikat Serwera
openssl req -newkey rsa:2048 -nodes -keyout server-key.pem -out server-req.pem -subj "/CN=vm-server"
openssl x509 -req -in server-req.pem -CA ca.pem -CAkey ca-key.pem -CAcreateserial -out server-cert.pem

# 3. Certyfikat Klienta (Agenta)
openssl req -newkey rsa:2048 -nodes -keyout client-key.pem -out client-req.pem -subj "/CN=vm-client-1"
openssl x509 -req -in client-req.pem -CA ca.pem -CAkey ca-key.pem -CAcreateserial -out client-cert.pem