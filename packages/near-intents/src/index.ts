/**
 * NEAR Intents is transport and liquidity for Edict, not the adjudicator.
 *
 * These helpers are deliberately pure. They never accept an API token,
 * private key, wallet client or signing callback. A customer wallet or payment
 * rail obtains signatures and submits the resulting quote/intent payloads.
 */

export * from './confidential.js';

import { createHash } from 'node:crypto';
import {
  GetExecutionStatusResponse,
  QuoteRequest,
  verifyQuoteSignature,
  type QuoteResponse,
} from '@defuse-protocol/one-click-sdk-typescript';
import type { LivenessFallback, SettlementBinding } from '@edict/core';
import { validateSettlementBinding } from '@edict/core';

export const NEAR_INTENTS_ROUTE_VERSION = 'edict-near-intents-route-1' as const;
export const NEAR_INTENTS_FUNDING_VERSION = 'edict-intents-funding-1' as const;
export const NEAR_INTENTS_MAINNET_CONTRACT = 'intents.near' as const;
export const ONE_CLICK_API_BASE_URL = 'https://1click.chaindefuser.com' as const;
export const INTENTS_SETTLEMENT_ADAPTER_VERSION = 'edict-customer-settlement-intents-v1' as const;

const SHA256_HEX = /^[0-9a-f]{64}$/;
const ATOMIC = /^(?:0|[1-9][0-9]*)$/;
const MAX_U128 = (1n << 128n) - 1n;
const ACCOUNT_ID = /^(?=.{2,64}$)[a-z0-9]+(?:[._-][a-z0-9]+)*$/;
const ASSET_ID = /^nep141:[a-z0-9]+(?:[._-][a-z0-9]+)*$/;
const MIN_ACTION_GAS = '30000000000000';

export type EdictRulingKind = 'requester_wins' | 'worker_wins' | 'split' | 'redo';

export type IntentsControllerRuling =
  | { kind: 'requester_wins' }
  | { kind: 'worker_wins' }
  | { kind: 'split'; requesterBps: number };

export interface NearIntentsRoute {
  version: typeof NEAR_INTENTS_ROUTE_VERSION;
  network: 'mainnet';
  intentsContract: string;
  settlementAccount: string;
  settlementAsset: string;
  removalIntentsAccount: string;
  fundingMode: 'signed_transfer_call';
  payoutMode: 'intents_account_claim';
  /** The experimental 1Click ft_transfer_call shortcut is never a release default. */
  directOneClickCallback: false;
}

export interface NearIntentsBindingOptions {
  resolutionTimeoutMs?: number;
  livenessFallback?: LivenessFallback;
}

export interface ProtectionFundingQuoteInput {
  originAsset: string;
  settlementAsset: string;
  principalAtomic: string;
  requesterIntentsAccount: string;
  source:
    | { kind: 'origin_chain'; refundTo: string }
    | { kind: 'intents'; signerId: string };
  deadline: string;
  slippageToleranceBps?: number;
  dry?: boolean;
  referral?: string;
  quoteWaitingTimeMs?: number;
}

export interface ClaimPayoutQuoteInput {
  settlementAsset: string;
  claimAtomic: string;
  partyIntentsAccount: string;
  destinationAsset: string;
  destinationAddress: string;
  deadline: string;
  slippageToleranceBps?: number;
  dry?: boolean;
  referral?: string;
  quoteWaitingTimeMs?: number;
}

export interface IntentsFundOrder {
  orderMandateSha256: string;
  settlementBindingSha256: string;
  workerIntentsAccount: string;
  principalAtomic: string;
  deadlineMs: number;
  acceptanceWindowMs: number;
  challengeWindowMs: number;
  resolutionTimeoutMs: number;
  livenessFallback: LivenessFallback;
  permittedRulings: EdictRulingKind[];
  disputeBondBps: number;
}

export interface IntentsTransferIntent {
  intent: 'transfer';
  receiver_id: string;
  tokens: Record<string, string>;
  memo: string;
  msg: string;
  min_gas: string;
}

export interface IntentsAuthCallIntent {
  intent: 'auth_call';
  contract_id: string;
  msg: string;
  min_gas: string;
}

export type IntentsPartyAction =
  | {
      action: 'deliver';
      order_mandate_sha256: number[];
      manifest_sha256: number[];
    }
  | {
      action: 'accept';
      order_mandate_sha256: number[];
    }
  | {
      action: 'open_held_dispute';
      order_mandate_sha256: number[];
      case_id_sha256: number[];
    }
  | {
      action: 'controller_fallback';
      order_mandate_sha256: number[];
      ruling: IntentsControllerRuling;
    };

export interface VerifiedFundingReceipt {
  version: 'edict-intents-funding-receipt-1';
  correlationId: string;
  quoteSignature: string;
  depositAddress: string;
  depositMemo?: string;
  amountOutAtomic: string;
  intentHashes: string[];
  nearTxHashes: string[];
  originChainTxHashes: string[];
  destinationChainTxHashes: string[];
}

export type OneClickQuoteRequest = QuoteRequest;
export type OneClickQuoteResponse = QuoteResponse;
export type OneClickExecutionStatus = GetExecutionStatusResponse;

function canonical(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .filter((key) => record[key] !== undefined)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonical(record[key])}`)
    .join(',')}}`;
}

function digest(value: unknown): string {
  return createHash('sha256').update(canonical(value)).digest('hex');
}

function assertAccountId(value: string, label: string): void {
  if (!ACCOUNT_ID.test(value)) throw new TypeError(`${label} must be a valid lowercase NEAR/Intents account id`);
}

function assertAssetId(value: string, label: string): void {
  if (!ASSET_ID.test(value)) throw new TypeError(`${label} must be a nep141: Intents asset id`);
}

function assertAtomic(value: string, label: string, allowZero = false): void {
  if (!ATOMIC.test(value) || (!allowZero && value === '0')) {
    throw new TypeError(`${label} must be a positive atomic-unit integer string`);
  }
  if (BigInt(value) > MAX_U128) {
    throw new TypeError(`${label} exceeds the uint128 settlement limit`);
  }
}

function assertSha256(value: string, label: string): void {
  if (!SHA256_HEX.test(value)) throw new TypeError(`${label} must be lowercase sha256 hex`);
}

function assertDeadline(value: string): void {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) throw new TypeError('deadline must be an ISO-8601 timestamp');
}

function assertSlippage(value: number): void {
  if (!Number.isInteger(value) || value < 0 || value > 10_000) {
    throw new TypeError('slippageToleranceBps must be an integer in [0, 10000]');
  }
}

function bytes32(value: string, label: string): number[] {
  assertSha256(value, label);
  return Array.from(Buffer.from(value, 'hex'));
}

function assertPositiveSafeInteger(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value <= 0) throw new TypeError(`${label} must be a positive safe integer`);
}

function assertRoute(route: NearIntentsRoute): void {
  if (route.version !== NEAR_INTENTS_ROUTE_VERSION || route.network !== 'mainnet') {
    throw new TypeError('NEAR Intents settlement supports mainnet route version 1 only');
  }
  if (route.intentsContract !== NEAR_INTENTS_MAINNET_CONTRACT) {
    throw new TypeError(`intentsContract must be ${NEAR_INTENTS_MAINNET_CONTRACT}`);
  }
  assertAccountId(route.settlementAccount, 'settlementAccount');
  assertAccountId(route.removalIntentsAccount, 'removalIntentsAccount');
  assertAssetId(route.settlementAsset, 'settlementAsset');
  if (route.removalIntentsAccount === route.settlementAccount) {
    throw new TypeError('the keyless settlement account must differ from the removal beneficiary');
  }
  if (route.fundingMode !== 'signed_transfer_call' || route.payoutMode !== 'intents_account_claim') {
    throw new TypeError('unsupported Intents funding or payout mode');
  }
  if (route.directOneClickCallback !== false) {
    throw new TypeError('experimental direct 1Click callbacks are not permitted in a release route');
  }
}

export function nearIntentsRoute(input: Omit<NearIntentsRoute,
  'version' | 'network' | 'intentsContract' | 'fundingMode' | 'payoutMode' | 'directOneClickCallback'>): NearIntentsRoute {
  const route: NearIntentsRoute = {
    version: NEAR_INTENTS_ROUTE_VERSION,
    network: 'mainnet',
    intentsContract: NEAR_INTENTS_MAINNET_CONTRACT,
    fundingMode: 'signed_transfer_call',
    payoutMode: 'intents_account_claim',
    directOneClickCallback: false,
    ...input,
  };
  assertRoute(route);
  return route;
}

export function nearIntentsRouteDigest(route: NearIntentsRoute): string {
  assertRoute(route);
  return digest(route);
}

export function nearIntentsAdapterRef(route: NearIntentsRoute): string {
  return `near-intents:v1:${route.settlementAccount}:${nearIntentsRouteDigest(route)}`;
}

export function nearIntentsSettlementBinding(
  route: NearIntentsRoute,
  options: NearIntentsBindingOptions = {},
): SettlementBinding {
  const binding: SettlementBinding = {
    custodyMode: 'M2_external_escrow',
    fundsController: 'customer_contract',
    adapterRef: nearIntentsAdapterRef(route),
    edictOperatorCanTransfer: false,
    edictOperatorCanFreeze: false,
    edictOperatorIsRequiredSigner: false,
    resolutionTimeoutMs: options.resolutionTimeoutMs ?? 72 * 60 * 60 * 1_000,
    livenessFallback: options.livenessFallback ?? 'controller_resolution',
  };
  const problems = validateSettlementBinding(binding);
  if (problems.length > 0) throw new TypeError(problems.join('; '));
  return binding;
}

/**
 * Quote cross-chain funding into the requester's Intents balance first. The
 * exact-output quote guarantees the subsequent settlement transfer is neither
 * short nor dependent on floating-point conversion.
 */
export function buildProtectionFundingQuote(input: ProtectionFundingQuoteInput): QuoteRequest {
  assertAssetId(input.originAsset, 'originAsset');
  assertAssetId(input.settlementAsset, 'settlementAsset');
  assertAtomic(input.principalAtomic, 'principalAtomic');
  assertAccountId(input.requesterIntentsAccount, 'requesterIntentsAccount');
  assertDeadline(input.deadline);
  const slippage = input.slippageToleranceBps ?? 100;
  assertSlippage(slippage);

  const depositType = input.source.kind === 'origin_chain'
    ? QuoteRequest.depositType.ORIGIN_CHAIN
    : QuoteRequest.depositType.INTENTS;
  const refundType = input.source.kind === 'origin_chain'
    ? QuoteRequest.refundType.ORIGIN_CHAIN
    : QuoteRequest.refundType.INTENTS;
  const refundTo = input.source.kind === 'origin_chain' ? input.source.refundTo : input.source.signerId;
  if (input.source.kind === 'intents') assertAccountId(input.source.signerId, 'source.signerId');
  if (refundTo.trim().length === 0) throw new TypeError('refundTo must not be empty');

  return {
    dry: input.dry ?? false,
    swapType: QuoteRequest.swapType.EXACT_OUTPUT,
    slippageTolerance: slippage,
    originAsset: input.originAsset,
    depositType,
    destinationAsset: input.settlementAsset,
    amount: input.principalAtomic,
    refundTo,
    refundType,
    recipient: input.requesterIntentsAccount,
    recipientType: QuoteRequest.recipientType.INTENTS,
    deadline: input.deadline,
    ...(input.referral === undefined ? {} : { referral: input.referral }),
    ...(input.quoteWaitingTimeMs === undefined ? {} : { quoteWaitingTimeMs: input.quoteWaitingTimeMs }),
  };
}

/** Build the party-controlled one-click withdrawal after an Edict claim is paid. */
export function buildClaimPayoutQuote(input: ClaimPayoutQuoteInput): QuoteRequest {
  assertAssetId(input.settlementAsset, 'settlementAsset');
  assertAssetId(input.destinationAsset, 'destinationAsset');
  assertAtomic(input.claimAtomic, 'claimAtomic');
  assertAccountId(input.partyIntentsAccount, 'partyIntentsAccount');
  assertDeadline(input.deadline);
  if (input.destinationAddress.trim().length === 0) throw new TypeError('destinationAddress must not be empty');
  const slippage = input.slippageToleranceBps ?? 100;
  assertSlippage(slippage);

  return {
    dry: input.dry ?? false,
    swapType: QuoteRequest.swapType.EXACT_INPUT,
    slippageTolerance: slippage,
    originAsset: input.settlementAsset,
    depositType: QuoteRequest.depositType.INTENTS,
    destinationAsset: input.destinationAsset,
    amount: input.claimAtomic,
    refundTo: input.partyIntentsAccount,
    refundType: QuoteRequest.refundType.INTENTS,
    recipient: input.destinationAddress,
    recipientType: QuoteRequest.recipientType.DESTINATION_CHAIN,
    deadline: input.deadline,
    ...(input.referral === undefined ? {} : { referral: input.referral }),
    ...(input.quoteWaitingTimeMs === undefined ? {} : { quoteWaitingTimeMs: input.quoteWaitingTimeMs }),
  };
}

/** Check every security-relevant echoed field before a wallet funds a quote. */
export function assertProtectionFundingQuoteFields(
  response: QuoteResponse,
  expected: QuoteRequest,
): void {
  if (canonical(response.quoteRequest) !== canonical(expected)) {
    throw new TypeError('1Click quote request echo does not match the locally constructed request');
  }
  if (expected.swapType !== QuoteRequest.swapType.EXACT_OUTPUT) {
    throw new TypeError('protection funding must use EXACT_OUTPUT');
  }
  if (expected.recipientType !== QuoteRequest.recipientType.INTENTS) {
    throw new TypeError('protection funding must land in the requester Intents account');
  }
  if (response.quote.amountOut !== expected.amount) {
    throw new TypeError('1Click quote does not provide the exact protected principal');
  }
  if (response.quote.customRecipientMsg !== undefined || expected.customRecipientMsg !== undefined) {
    throw new TypeError('experimental 1Click customRecipientMsg is forbidden for protection funding');
  }
  if (!expected.dry && (response.quote.depositAddress?.trim().length ?? 0) === 0) {
    throw new TypeError('executable 1Click quote has no deposit address');
  }
  if (response.correlationId.trim().length === 0 || response.signature.trim().length === 0) {
    throw new TypeError('1Click quote is missing its correlation id or signature');
  }
  assertDeadline(response.timestamp);
}

export function assertSignedProtectionFundingQuote(
  response: QuoteResponse,
  expected: QuoteRequest,
  managerPublicKey?: string,
): void {
  if (!verifyQuoteSignature(response, managerPublicKey)) {
    throw new TypeError('1Click quote signature is invalid');
  }
  assertProtectionFundingQuoteFields(response, expected);
}

/** Check a party's post-settlement payout quote before it signs the withdrawal. */
export function assertClaimPayoutQuoteFields(response: QuoteResponse, expected: QuoteRequest): void {
  if (canonical(response.quoteRequest) !== canonical(expected)) {
    throw new TypeError('1Click payout quote request echo does not match the locally constructed request');
  }
  if (expected.swapType !== QuoteRequest.swapType.EXACT_INPUT
      || expected.depositType !== QuoteRequest.depositType.INTENTS
      || expected.refundType !== QuoteRequest.refundType.INTENTS
      || expected.recipientType !== QuoteRequest.recipientType.DESTINATION_CHAIN) {
    throw new TypeError('claim payout must be an INTENTS exact-input withdrawal to a destination chain');
  }
  if (expected.refundTo.trim().length === 0 || response.quote.amountIn !== expected.amount) {
    throw new TypeError('1Click payout quote does not spend the exact fixed-owner claim');
  }
  if (response.quote.customRecipientMsg !== undefined || expected.customRecipientMsg !== undefined) {
    throw new TypeError('experimental 1Click customRecipientMsg is forbidden for claim payout');
  }
  if (!expected.dry && (response.quote.depositAddress?.trim().length ?? 0) === 0) {
    throw new TypeError('executable 1Click payout quote has no Intents deposit account');
  }
  if (response.correlationId.trim().length === 0 || response.signature.trim().length === 0) {
    throw new TypeError('1Click payout quote is missing its correlation id or signature');
  }
  assertDeadline(response.timestamp);
}

export function assertSignedClaimPayoutQuote(
  response: QuoteResponse,
  expected: QuoteRequest,
  managerPublicKey?: string,
): void {
  if (!verifyQuoteSignature(response, managerPublicKey)) {
    throw new TypeError('1Click payout quote signature is invalid');
  }
  assertClaimPayoutQuoteFields(response, expected);
}

/**
 * A SUCCESS status is evidence of transport only. The subsequent signed
 * transfer-call is what moves the exact amount into Edict's bounded state
 * machine and binds it to an order.
 */
export function verifiedFundingReceipt(
  status: GetExecutionStatusResponse,
  expected: QuoteRequest,
  managerPublicKey?: string,
): VerifiedFundingReceipt {
  assertSignedProtectionFundingQuote(status.quoteResponse, expected, managerPublicKey);
  if (status.status !== GetExecutionStatusResponse.status.SUCCESS) {
    throw new TypeError(`1Click funding is not successful (status ${status.status})`);
  }
  if (status.swapDetails.amountOut !== expected.amount) {
    throw new TypeError('successful 1Click status does not report the exact protected principal');
  }
  const quote = status.quoteResponse.quote;
  if (quote.depositAddress === undefined || quote.depositAddress.trim().length === 0) {
    throw new TypeError('successful 1Click status has no deposit address');
  }
  return {
    version: 'edict-intents-funding-receipt-1',
    correlationId: status.correlationId,
    quoteSignature: status.quoteResponse.signature,
    depositAddress: quote.depositAddress,
    ...(quote.depositMemo === undefined ? {} : { depositMemo: quote.depositMemo }),
    amountOutAtomic: status.swapDetails.amountOut,
    intentHashes: [...status.swapDetails.intentHashes],
    nearTxHashes: [...status.swapDetails.nearTxHashes],
    originChainTxHashes: status.swapDetails.originChainTxHashes.map(({ hash }) => hash),
    destinationChainTxHashes: status.swapDetails.destinationChainTxHashes.map(({ hash }) => hash),
  };
}

function assertFundOrder(order: IntentsFundOrder): void {
  assertSha256(order.orderMandateSha256, 'orderMandateSha256');
  assertSha256(order.settlementBindingSha256, 'settlementBindingSha256');
  assertAccountId(order.workerIntentsAccount, 'workerIntentsAccount');
  assertAtomic(order.principalAtomic, 'principalAtomic');
  assertPositiveSafeInteger(order.deadlineMs, 'deadlineMs');
  assertPositiveSafeInteger(order.acceptanceWindowMs, 'acceptanceWindowMs');
  assertPositiveSafeInteger(order.challengeWindowMs, 'challengeWindowMs');
  assertPositiveSafeInteger(order.resolutionTimeoutMs, 'resolutionTimeoutMs');
  if (order.challengeWindowMs < 2 * 60 * 60 * 1_000 || order.challengeWindowMs > 24 * 60 * 60 * 1_000) {
    throw new TypeError('challengeWindowMs must be between 2 and 24 hours');
  }
  if (order.resolutionTimeoutMs <= order.challengeWindowMs) {
    throw new TypeError('resolutionTimeoutMs must exceed challengeWindowMs');
  }
  if (!Number.isInteger(order.disputeBondBps) || order.disputeBondBps < 500 || order.disputeBondBps > 1_000) {
    throw new TypeError('disputeBondBps must be between 500 and 1000');
  }
  disputeBondAtomic(order.principalAtomic, order.disputeBondBps);
  if (order.permittedRulings.length === 0 || new Set(order.permittedRulings).size !== order.permittedRulings.length) {
    throw new TypeError('permittedRulings must be non-empty and unique');
  }
}

/** Build the exact signed Transfer intent consumed by mt_on_transfer. */
export function buildProtectionFundingTransfer(
  route: NearIntentsRoute,
  order: IntentsFundOrder,
): IntentsTransferIntent {
  assertRoute(route);
  assertFundOrder(order);
  const action = {
    version: NEAR_INTENTS_FUNDING_VERSION,
    action: 'fund' as const,
    args: {
      order_mandate_sha256: bytes32(order.orderMandateSha256, 'orderMandateSha256'),
      settlement_binding_sha256: bytes32(order.settlementBindingSha256, 'settlementBindingSha256'),
      worker: order.workerIntentsAccount,
      principal: order.principalAtomic,
      deadline_ms: order.deadlineMs,
      acceptance_window_ms: order.acceptanceWindowMs,
      challenge_window_ms: order.challengeWindowMs,
      resolution_timeout_ms: order.resolutionTimeoutMs,
      liveness_fallback: order.livenessFallback,
      permitted_rulings: order.permittedRulings,
      dispute_bond_bps: order.disputeBondBps,
    },
  };
  return {
    intent: 'transfer',
    receiver_id: route.settlementAccount,
    tokens: { [route.settlementAsset]: order.principalAtomic },
    memo: `edict-fund:${order.orderMandateSha256}`,
    msg: canonical(action),
    min_gas: MIN_ACTION_GAS,
  };
}

export function disputeBondAtomic(principalAtomic: string, disputeBondBps: number): string {
  assertAtomic(principalAtomic, 'principalAtomic');
  if (!Number.isInteger(disputeBondBps) || disputeBondBps < 500 || disputeBondBps > 1_000) {
    throw new TypeError('disputeBondBps must be between 500 and 1000');
  }
  const bond = BigInt(principalAtomic) * BigInt(disputeBondBps) / 10_000n;
  if (bond === 0n) {
    throw new TypeError('principalAtomic is too small for a positive atomic Bond');
  }
  return bond.toString();
}

/** The first dispute transfers the exact same-asset Bond with its callback. */
export function buildDisputeBondTransfer(
  route: NearIntentsRoute,
  input: { orderMandateSha256: string; caseIdSha256: string; bondAtomic: string },
): IntentsTransferIntent {
  assertRoute(route);
  assertSha256(input.orderMandateSha256, 'orderMandateSha256');
  assertSha256(input.caseIdSha256, 'caseIdSha256');
  assertAtomic(input.bondAtomic, 'bondAtomic');
  const action = {
    version: NEAR_INTENTS_FUNDING_VERSION,
    action: 'open_dispute' as const,
    order_mandate_sha256: bytes32(input.orderMandateSha256, 'orderMandateSha256'),
    case_id_sha256: bytes32(input.caseIdSha256, 'caseIdSha256'),
  };
  return {
    intent: 'transfer',
    receiver_id: route.settlementAccount,
    tokens: { [route.settlementAsset]: input.bondAtomic },
    memo: `edict-bond:${input.orderMandateSha256}`,
    msg: canonical(action),
    min_gas: MIN_ACTION_GAS,
  };
}

/** Any supported wallet standard can sign this non-monetary auth_call intent. */
export function buildPartyAuthCall(
  route: NearIntentsRoute,
  action: IntentsPartyAction,
): IntentsAuthCallIntent {
  assertRoute(route);
  return {
    intent: 'auth_call',
    contract_id: route.settlementAccount,
    msg: canonical({ version: NEAR_INTENTS_FUNDING_VERSION, ...action }),
    min_gas: MIN_ACTION_GAS,
  };
}

export function deliverAction(orderMandateSha256: string, manifestSha256: string): IntentsPartyAction {
  return {
    action: 'deliver',
    order_mandate_sha256: bytes32(orderMandateSha256, 'orderMandateSha256'),
    manifest_sha256: bytes32(manifestSha256, 'manifestSha256'),
  };
}

export function acceptAction(orderMandateSha256: string): IntentsPartyAction {
  return {
    action: 'accept',
    order_mandate_sha256: bytes32(orderMandateSha256, 'orderMandateSha256'),
  };
}

export function openHeldDisputeAction(
  orderMandateSha256: string,
  caseIdSha256: string,
): IntentsPartyAction {
  return {
    action: 'open_held_dispute',
    order_mandate_sha256: bytes32(orderMandateSha256, 'orderMandateSha256'),
    case_id_sha256: bytes32(caseIdSha256, 'caseIdSha256'),
  };
}

export function controllerFallbackAction(
  orderMandateSha256: string,
  ruling: IntentsControllerRuling,
): IntentsPartyAction {
  if (ruling.kind === 'split') {
    if (!Number.isInteger(ruling.requesterBps) || ruling.requesterBps < 0 || ruling.requesterBps > 10_000) {
      throw new TypeError('controller fallback requesterBps must be an integer in [0, 10000]');
    }
  }
  return {
    action: 'controller_fallback',
    order_mandate_sha256: bytes32(orderMandateSha256, 'orderMandateSha256'),
    ruling,
  };
}
