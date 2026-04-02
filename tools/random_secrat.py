import secrets, base64, hashlib

# Generate two random secrets
secretA = base64.urlsafe_b64encode(secrets.token_bytes(24)).decode().rstrip("=")
secretB = base64.urlsafe_b64encode(secrets.token_bytes(24)).decode().rstrip("=")

# Compute individual hashes
hashA = hashlib.sha256(secretA.encode()).hexdigest()
hashB = hashlib.sha256(secretB.encode()).hexdigest()

# Compute combined hash for "A:B"
combo = f"{secretA}:{secretB}"
combo_hash = hashlib.sha256(combo.encode()).hexdigest()

# Print everything clearly
print("🔐 Developer Secrets\n--------------------")
print(f"Secret A: {secretA}")
print(f"Secret B: {secretB}\n")

print("✅ Hashes to paste into code")
print(f"EXPECTED_HASH_A = \"{hashA}\"")
print(f"EXPECTED_HASH_B = \"{hashB}\"")
print(f"COMBINED_EXPECTED_HASH = \"{combo_hash}\"")

print("\n💡 Save the two secrets (A and B) in:")
print("   C:\\ProgramData\\Keyquorum\\dev.unlock  (two lines)")