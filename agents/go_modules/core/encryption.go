func (a *{AGENT_STRUCT_NAME}) {AGENT_ENCRYPT_DATA_FUNC}(data string) (string, error) {
	if a.{AGENT_SECRET_KEY_FIELD} == nil {
		return data, nil
	}

	encrypted, err := fernet.EncryptAndSign([]byte(data), a.{AGENT_SECRET_KEY_FIELD})
	if err != nil {
		return data, err
	}

	return base64.StdEncoding.EncodeToString(encrypted), nil  // Use standard base64 encoding for consistency
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_DECRYPT_DATA_FUNC}(encryptedData string) (string, error) {
	if a.{AGENT_SECRET_KEY_FIELD} == nil {
		return encryptedData, nil
	}

	decoded, err := base64.URLEncoding.DecodeString(encryptedData)
	if err != nil {
		decoded, err = base64.StdEncoding.DecodeString(encryptedData)
		if err != nil {
			return encryptedData, err
		}
	}

	keys := []*fernet.Key{a.{AGENT_SECRET_KEY_FIELD}}
	decrypted := fernet.VerifyAndDecrypt(decoded, 0, keys) // 0 TTL means no expiration checking

	if decrypted == nil {
		return encryptedData, fmt.Errorf("failed to decrypt data")
	}

	return string(decrypted), nil
}