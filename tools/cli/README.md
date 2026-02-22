--------------
cli_decrypt_store.py 
--------------

## identity file decrypt
	python cli_decrypt_store.py --file "...\Keyquorum\Users\KQ_Dev\Main\KQ_Dev.kq_id" --pretty
	
## vault decrypt - Current 
	python cli_decrypt_store.py --file "...\KQ_Dev4\Main\Vault\KQ_Dev4.kq_user" --salt "...\KQ_Dev4\KQ_Store\kq_user_KQ_Dev4.slt" --pretty

## vault decrypt - salt store in identity 
	upgreade !!


--------------
Output to cli or file
--------------
--out "C:\temp\vault_decrypted.json" --pretty # might not be safe

--------------
# Requirements
--------------
This script needs:

	- argon2-cffi (for Argon2id)
	- cryptography (for AESGCM)

