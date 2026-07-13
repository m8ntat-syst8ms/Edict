import type { ProtectionProjection } from './types.js';
import {
  PROTECTION_REGISTRATION_VERSION,
  type ProtectResultLike,
  type ProtectionRegistration,
  type RegistrationFromProtectOptions,
  type SignedActionEnvelope,
  type SignedActionName,
} from './types.js';

export function registrationFromProtectResult(
  result: ProtectResultLike,
  options: RegistrationFromProtectOptions,
): ProtectionRegistration {
  return {
    version: PROTECTION_REGISTRATION_VERSION,
    mandate: structuredClone(result.mandate),
    mandateHash: result.mandateHash,
    legalPolicyHash: result.legalPolicyHash,
    profile: structuredClone(options.profile),
    profileHash: result.profileHash,
    evidenceCommitments: structuredClone(result.evidenceCommitments),
    ...('intents' in options && options.intents !== undefined
      ? { intents: structuredClone(options.intents) }
      : { nativeNear: structuredClone(options.nativeNear) }),
    ...(options.integrationRef !== undefined ? { integrationRef: options.integrationRef } : {}),
    ...(options.standingChallengeAuthorization !== undefined
      ? { standingChallengeAuthorization: structuredClone(options.standingChallengeAuthorization) }
      : {}),
  };
}

export interface ProtectionRuntimeHttpClientOptions {
  baseUrl: string;
  apiToken?: string;
  fetchImpl?: typeof fetch;
}

/** Small integration client; all settlement and wallet signatures stay caller-side. */
export class ProtectionRuntimeHttpClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;

  constructor(readonly options: ProtectionRuntimeHttpClientOptions) {
    const url = new URL(options.baseUrl);
    const loopbackHttp = url.protocol === 'http:' && url.hostname === '127.0.0.1';
    if (url.protocol !== 'https:' && !loopbackHttp) {
      throw new TypeError('runtime base URL must use HTTPS (or loopback HTTP for development)');
    }
    if (url.username !== '' || url.password !== '') {
      throw new TypeError('runtime base URL must not contain credentials');
    }
    if (url.search !== '' || url.hash !== '') {
      throw new TypeError('runtime base URL must not contain a query or fragment');
    }
    this.baseUrl = url.toString().replace(/\/+$/, '');
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  private async request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const response = await this.fetchImpl(`${this.baseUrl}${path}`, {
      ...init,
      headers: {
        ...(init.body !== undefined ? { 'content-type': 'application/json' } : {}),
        ...(this.options.apiToken !== undefined ? { authorization: `Bearer ${this.options.apiToken}` } : {}),
        ...init.headers,
      },
    });
    const body = await response.json() as { message?: string } & T;
    if (!response.ok) throw new Error(body.message ?? `Edict Protect runtime returned HTTP ${response.status}`);
    return body;
  }

  async protect(
    result: ProtectResultLike,
    options: RegistrationFromProtectOptions,
  ): Promise<ProtectionProjection> {
    const registration = registrationFromProtectResult(result, options);
    const body = await this.request<{ protection: ProtectionProjection }>('/v1/protections', {
      method: 'POST',
      body: JSON.stringify({ registration }),
    });
    return body.protection;
  }

  async activity(): Promise<ProtectionProjection[]> {
    const body = await this.request<{ activity: ProtectionProjection[] }>('/v1/activity');
    return body.activity;
  }

  async action<A extends SignedActionName>(envelope: SignedActionEnvelope<A>): Promise<unknown> {
    return this.request(`/v1/protections/${envelope.protectionId}/actions`, {
      method: 'POST',
      body: JSON.stringify(envelope),
    });
  }
}
