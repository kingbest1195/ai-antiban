import type { CheckStatus } from "./audit";

export type CardFunding = "credit" | "debit" | "prepaid" | "charge" | "unknown";

export type BinSource =
  | "localOverlay"
  | "cache"
  | "proxyApi"
  | "fallbackPublicApi"
  | "fallbackUnknown";

export type ClaudeWebVerdict =
  | "safeAligned"
  | "needsMatchingIpBilling"
  | "highKycRisk"
  | "blocked";

export interface BinReport {
  binPrefix: string;
  status: CheckStatus;
  scheme: string | null;
  funding: CardFunding;
  isPrepaid: boolean | null;
  isCommercial: boolean | null;
  isReloadable: boolean | null;
  cardCategory: string | null;
  countryCode: string | null;
  issuerName: string | null;
  knownFintechLabel: string | null;
  source: BinSource;
  claudeWebVerdict: ClaudeWebVerdict;
  warnings: string[];
}

export type ReadinessTier = "green" | "yellow" | "red";

export type PaymentChannel =
  | "directCard"
  | "googlePayWeb"
  | "applePayWeb"
  | "appleIAP"
  | "api";

export type SubscriptionPlan = "pro" | "max" | "api" | "unknown";

export interface AxisScore {
  id: string;
  label: string;
  score: number;
  maxScore: number;
  status: CheckStatus;
  notes: string[];
}

export interface PaymentReadinessAxes {
  networkBase: AxisScore;
  cardBin: AxisScore;
  geoBillingParity: AxisScore;
  channelEnvWarmup: AxisScore;
}

export interface PaymentReadinessReport {
  score: number;
  tier: ReadinessTier;
  axes: PaymentReadinessAxes;
  warnings: string[];
  blockers: string[];
  recommendedAction: string | null;
  requiresMatchingBilling: boolean;
  failClosedBin: boolean;
  channel: PaymentChannel;
  evaluatedAt: number;
}

export interface EvaluatePaymentReadinessParams {
  bin?: string | null;
  billingCountry?: string | null;
  googleProfileCountry?: string | null;
  appleIdCountry?: string | null;
  channel?: PaymentChannel;
  inCleanRoom?: boolean;
  plan?: SubscriptionPlan;
  profileId?: string | null;
  provider?: string | null;
  accountAgeConfirmed96h?: boolean;
}

export interface CheckoutRiskAlert {
  domain: string;
  score: number;
  tier: ReadinessTier;
  reason: string;
  blockers: string[];
  warnings: string[];
  recommendedAction?: string | null;
}

export interface PostPaymentQuarantine {
  startedAt: number;
  expiresAt: number;
  pinnedRouteId?: string | null;
  pinnedExitIp?: string | null;
  pinnedAsn?: number | null;
  pinnedCountry?: string | null;
  overriddenAt?: number | null;
}

export interface PostPaymentQuarantineStatus {
  active: boolean;
  remainingHours: number;
  remainingSecs: number;
  quarantine: PostPaymentQuarantine | null;
  warning: string | null;
}

export interface ActivateQuarantineParams {
  profileId?: string | null;
  routeId?: string | null;
  exitIp?: string | null;
  exitAsn?: number | null;
  exitCountry?: string | null;
}

export type PassportChannel = "directCard" | "appleIAP" | "api";

export interface PaymentPassport {
  profileId: string;
  binPrefix: string;
  cardCountry: string;
  channel: PassportChannel;
  billingCountry: string;
  exitIp: string;
  exitAsn?: number | null;
  paidAt: number;
}

export interface RenewalCheckInput {
  binPrefix?: string | null;
  cardCountry?: string | null;
  channel?: PassportChannel | null;
  billingCountry?: string | null;
  exitIp?: string | null;
  exitAsn?: number | null;
}

export interface PassportVerificationResult {
  matched: boolean;
  mismatches: string[];
  warnings: string[];
  passport: PaymentPassport;
}
