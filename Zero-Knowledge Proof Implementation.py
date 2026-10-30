import hashlib
import secrets

# Public parameters
p = 23          # Prime number
q = 11          # Order of the subgroup
g = 2           # Generator

# -----------------------------
# PROVER
# -----------------------------

# Secret value (NEVER shared)
secret = 7

# Calculate public value
public_value = pow(g, secret, p)

print("=== Zero-Knowledge Proof ===")
print("Public Value:", public_value)
print("Secret is kept hidden.\n")

# Generate random number
r = secrets.randbelow(q)

# Commitment
commitment = pow(g, r, p)

print("Prover sends Commitment:", commitment)

# -----------------------------
# VERIFIER
# -----------------------------

# Generate challenge
challenge = secrets.randbelow(q)

print("Verifier sends Challenge:", challenge)

# -----------------------------
# PROVER RESPONSE
# -----------------------------

# Response = r + challenge * secret
response = (r + challenge * secret) % q

print("Prover sends Response:", response)

# -----------------------------
# VERIFICATION
# -----------------------------

left_side = pow(g, response, p)

right_side = (
    commitment *
    pow(public_value, challenge, p)
) % p

print("\n=== Verification ===")

print("Left Side :", left_side)
print("Right Side:", right_side)

if left_side == right_side:
    print("\n✓ Zero-Knowledge Proof Successful!")
    print("The prover has demonstrated knowledge of the secret.")
else:
    print("\n✗ Zero-Knowledge Proof Failed!")