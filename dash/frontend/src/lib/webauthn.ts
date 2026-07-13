function decodeBase64Url(value: string): ArrayBuffer {
  const padded = value
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    .padEnd(Math.ceil(value.length / 4) * 4, '=');
  const bytes = Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
  return bytes.buffer;
}

function encodeBase64Url(value: ArrayBuffer | null): string | null {
  if (value === null) return null;
  const bytes = new Uint8Array(value);
  let binary = '';
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function credentialJson(value: Credential): Record<string, unknown> {
  const credential = value as PublicKeyCredential;
  const response = credential.response;
  const base = {
    id: credential.id,
    rawId: encodeBase64Url(credential.rawId),
    type: credential.type,
    clientExtensionResults: credential.getClientExtensionResults(),
  };
  if (response instanceof AuthenticatorAttestationResponse) {
    return {
      ...base,
      response: {
        clientDataJSON: encodeBase64Url(response.clientDataJSON),
        attestationObject: encodeBase64Url(response.attestationObject),
        transports: response.getTransports?.() ?? [],
      },
    };
  }
  const assertion = response as AuthenticatorAssertionResponse;
  return {
    ...base,
    response: {
      clientDataJSON: encodeBase64Url(assertion.clientDataJSON),
      authenticatorData: encodeBase64Url(assertion.authenticatorData),
      signature: encodeBase64Url(assertion.signature),
      userHandle: encodeBase64Url(assertion.userHandle),
    },
  };
}

export async function createWebAuthnCredential(
  source: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  if (!navigator.credentials?.create) throw new Error('This browser does not support WebAuthn.');
  const user = source.user as Record<string, unknown>;
  const exclude = (source.excludeCredentials as Array<Record<string, unknown>> | undefined) ?? [];
  const publicKey = {
    ...source,
    challenge: decodeBase64Url(String(source.challenge)),
    user: { ...user, id: decodeBase64Url(String(user.id)) },
    excludeCredentials: exclude.map((item) => ({
      ...item,
      id: decodeBase64Url(String(item.id)),
    })),
  } as PublicKeyCredentialCreationOptions;
  const created = await navigator.credentials.create({ publicKey });
  if (!created) throw new Error('Security-key enrollment was cancelled.');
  return credentialJson(created);
}

export async function getWebAuthnCredential(
  source: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  if (!navigator.credentials?.get) throw new Error('This browser does not support WebAuthn.');
  const allowed = (source.allowCredentials as Array<Record<string, unknown>> | undefined) ?? [];
  const publicKey = {
    ...source,
    challenge: decodeBase64Url(String(source.challenge)),
    allowCredentials: allowed.map((item) => ({
      ...item,
      id: decodeBase64Url(String(item.id)),
    })),
  } as PublicKeyCredentialRequestOptions;
  const result = await navigator.credentials.get({ publicKey });
  if (!result) throw new Error('Security-key verification was cancelled.');
  return credentialJson(result);
}
