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
  | "googlePlayIap"
  | "api";

export type AiPaymentService =
  | "claude_pro"
  | "claude_max"
  | "chatgpt"
  | "cursor"
  | "gemini";

export type PaymentRail = "rub_sbp" | "crypto_usdt" | "foreign_bank_card";

export type KycRiskTier = "minimal" | "low" | "medium" | "high" | "critical";

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
  targetService?: AiPaymentService | null;
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
  binPrefix?: string | null;
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

export type PassportChannel = "directCard" | "appleIAP" | "googlePlayIap" | "api";

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

export type BinRadarStatus = "sufficient" | "insufficient_data" | "critical";

export interface BinRadarWindowStats {
  n: number;
  success_pct: number;
  soft_decline_pct: number;
  instant_kyc_pct: number;
  instant_ban_pct: number;
}

export interface BinRadarLookupStats {
  binPrefix: string;
  service: AiPaymentService;
  status: BinRadarStatus;
  sampleSize14d: number;
  sampleSize30d: number;
  window14d: BinRadarWindowStats | null;
  window30d: BinRadarWindowStats | null;
  riskPct14d: number | null;
  criticalWarning: boolean;
  summaryRu: string;
}

export type GeoMatchClass =
  | "full_match"
  | "ip_mismatch"
  | "billing_mismatch"
  | "triple_mismatch";

export type WarmupBucket = "lt_24h" | "24_96h" | "gt_96h";

export type PaymentOutcome =
  | "success"
  | "soft_decline"
  | "instant_kyc"
  | "instant_ban";

export interface BinRadarReport {
  bin_prefix: string;
  service: AiPaymentService;
  channel:
    | "stripe_web_card"
    | "stripe_google_pay"
    | "stripe_apple_pay"
    | "apple_iap"
    | "google_play_iap";
  geo_match: GeoMatchClass;
  warmup_bucket: WarmupBucket;
  outcome: PaymentOutcome;
  client_version: string;
}

export interface AdvisorNetworkContext {
  exit_country?: string | null;
  trust_score: number;
  clean_room_ready: boolean;
  is_zastava_key_active: boolean;
}

export interface AdvisorQuery {
  target_service: AiPaymentService;
  has_iphone_apple_id: boolean;
  available_bin_prefix?: string | null;
  payment_rails: PaymentRail[];
  willing_to_warmup_96h: boolean;
  google_payments_country?: string | null;
  is_new_google_account?: boolean | null;
  network_state: AdvisorNetworkContext;
}

export interface AdvisorRoute {
  route_id: string;
  title: string;
  kyc_risk_tier: KycRiskTier;
  estimated_fees: string;
  provider_ids: string[];
  checklist: string[];
  warnings?: string[];
  demoted_provider_ids?: string[];
}

export interface BlockedRouteWarning {
  route_id: string;
  title: string;
  kyc_risk_tier: KycRiskTier;
  reason: string;
  explanation: string;
  rescue_route_id?: string | null;
}

export interface AdvisorPlan {
  primary: AdvisorRoute;
  fallbacks: AdvisorRoute[];
  blocked_red_flags: BlockedRouteWarning[];
}

export type ProviderStatus = "active" | "demoted_warning" | "blacklist";

export interface ProviderManifestEntry {
  id: string;
  name: string;
  category: string;
  tier: string;
  status: ProviderStatus;
  known_bin_prefixes: string[];
  supported_rails: string[];
  supported_services: AiPaymentService[];
  fees_summary: string;
  warnings_ru: string[];
  affiliate_url?: string | null;
}

export interface ServiceDemoteStatus {
  service: AiPaymentService;
  status: ProviderStatus;
  rate14d: number;
  sampleSize14d: number;
  reasonRu?: string | null;
}

export interface EvaluatedProvider {
  entry: ProviderManifestEntry;
  effectiveStatus: ProviderStatus;
  globalDemoted: boolean;
  perService: ServiceDemoteStatus[];
  demoteReasonRu?: string | null;
}

export interface BlacklistedManifestEntry {
  id: string;
  name: string;
  reason_ru: string;
}

export interface EvaluatedProvidersManifest {
  schemaVersion: number;
  generatedAtUtc: string;
  providers: EvaluatedProvider[];
  blacklist: BlacklistedManifestEntry[];
}
