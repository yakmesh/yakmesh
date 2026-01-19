/**
 * YAKMESH TypeScript Definitions
 * Post-quantum secure P2P mesh network
 * @version 2.2.0
 */

// ============================================================
// DOKO Identity System
// ============================================================

export interface DOKOClaims {
  nodeId: string;
  displayName?: string;
  email?: string;
  domains?: DomainClaim[];
  userId?: string;
  [key: string]: unknown;
}

export interface DomainClaim {
  domain: string;
  verified: boolean;
  verifiedAt?: number;
}

export interface DOKODocument {
  dokoId: string;
  type: 'node' | 'user' | 'service' | 'device';
  version: string;
  nodeId: string;
  publicKey: string;
  backupPublicKey: string;
  claims: DOKOClaims;
  issuedAt: number;
  expiresAt: number;
  signature: string;
  backupSignature: string;
}

export interface RevocationCertificate {
  type: 'revocation';
  dokoId: string;
  reason: RevocationReason;
  revokedAt: number;
  signature: string;
}

export type RevocationReason = 
  | 'KEY_COMPROMISED'
  | 'DOKO_SUPERSEDED'
  | 'IDENTITY_RETIRED'
  | 'LOST_ACCESS'
  | 'AFFILIATION_ENDED';

export declare const REVOCATION_REASONS: Record<RevocationReason, RevocationReason>;

export declare class DOKOGenerator {
  constructor(options?: { keyPair?: KeyPair; backupKeyPair?: KeyPair });
  generate(type: DOKODocument['type'], claims: DOKOClaims, validityDays?: number): DOKODocument;
  getPublicKey(): string;
  getBackupPublicKey(): string;
}

export declare class DOKOValidator {
  constructor();
  validate(doko: DOKODocument): ValidationResult;
  verifySignature(doko: DOKODocument): boolean;
}

export declare class DOKORevocation {
  constructor(options: { generator: DOKOGenerator; nodeId: string; network?: unknown });
  revoke(dokoId: string, reason: RevocationReason, privateKey: Uint8Array): RevocationCertificate;
  createEmergencyCertificate(dokoId: string, reason: RevocationReason, backupPrivateKey: Uint8Array): RevocationCertificate;
  verify(certificate: RevocationCertificate, publicKey: Uint8Array): boolean;
  isRevoked(dokoId: string): boolean;
  getRevocationCertificate(dokoId: string): RevocationCertificate | null;
}

export declare class DOKOStore {
  constructor(storagePath?: string);
  save(doko: DOKODocument): void;
  get(dokoId: string): DOKODocument | null;
  getByNodeId(nodeId: string): DOKODocument | null;
  delete(dokoId: string): boolean;
  list(): DOKODocument[];
  getStats(): { total: number; byType: Record<string, number> };
}

// ============================================================
// YAK:// Protocol
// ============================================================

export interface Bookmark {
  target: string;
  createdAt: number;
  updatedAt: number;
}

export interface RemoteBookmarkEntry {
  bookmarks: Record<string, Bookmark>;
  publishedAt: number;
  signature?: string;
}

export declare class BookmarkManager {
  constructor(pathOrOptions?: string | { dataDir?: string });
  add(name: string, target: string): boolean;
  remove(name: string): boolean;
  get(name: string): string | null;
  list(): Record<string, Bookmark>;
  resolve(yakPath: string): string | null;
}

export declare class RemoteBookmarkSync {
  constructor(options: {
    nodeId: string;
    network?: unknown;
    localBookmarks?: BookmarkManager;
    dataDir?: string;
  });
  subscribe(nodeId: string): void;
  unsubscribe(nodeId: string): boolean;
  getSubscriptions(): string[];
  publish(listName: string, bookmarks?: string[]): void;
  getRemoteBookmarks(): Map<string, RemoteBookmarkEntry>;
  resolveRemote(name: string): string | null;
  getStatus(): {
    subscriptions: number;
    remoteBookmarks: number;
    publishedLists: number;
    lastSync: number | null;
  };
}

export declare function parseYakUrl(url: string): {
  protocol: string;
  host: string;
  path: string;
  hash?: string;
} | null;

export declare function yakToHttp(yakUrl: string, port?: number): string | null;
export declare function httpToYak(httpUrl: string): string | null;
export declare function getBookmarkManager(): BookmarkManager;
export declare function getRemoteBookmarkSync(options?: { nodeId?: string; network?: unknown }): RemoteBookmarkSync;

// ============================================================
// Oracle System
// ============================================================

export interface TimeSourceResult {
  timestamp: number;
  source: string;
  latency: number;
  confidence: number;
}

export interface PhaseInfo {
  phase: number;
  epoch: number;
  phaseStart: number;
  phaseEnd: number;
  epochStart: number;
}

export declare class TimeSource {
  constructor(options?: { sources?: string[] });
  getTime(): Promise<TimeSourceResult>;
  getNetworkTime(): Promise<number>;
}

export declare class PhaseEpochManager {
  constructor(options?: { phaseDuration?: number; epochLength?: number });
  getCurrentPhase(): PhaseInfo;
  getPhaseAtTime(timestamp: number): PhaseInfo;
  onPhaseChange(callback: (phase: PhaseInfo) => void): void;
}

// ============================================================
// Mesh Network
// ============================================================

export interface PeerInfo {
  nodeId: string;
  address: string;
  port: number;
  publicKey: string;
  lastSeen: number;
}

export interface GossipMessage {
  type: string;
  payload: unknown;
  timestamp: number;
  signature?: string;
}

export declare class MeshNetwork {
  constructor(options: { nodeId: string; port?: number });
  start(): Promise<void>;
  stop(): Promise<void>;
  connect(address: string, port: number): Promise<boolean>;
  broadcast(message: GossipMessage): void;
  on(event: string, handler: (...args: unknown[]) => void): void;
  getPeers(): PeerInfo[];
  getStats(): {
    connectedPeers: number;
    messagesSent: number;
    messagesReceived: number;
  };
}

// ============================================================
// Security Modules
// ============================================================

export interface ValidationResult {
  valid: boolean;
  errors?: string[];
}

export interface KeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export declare class NamcheGateway {
  constructor(options?: { identity?: unknown });
  verify(doko: DOKODocument): Promise<ValidationResult>;
  lookupByHash(dokoHash: string): DOKODocument | null;
  lookupByNodeId(nodeId: string): DOKODocument | null;
  lookupByDomain(domain: string): DOKODocument | null;
  getStats(): {
    cacheSize: number;
    revocationsCount: number;
  };
}

export declare class DomainConsensus {
  constructor(options: { identity: unknown; gateway?: NamcheGateway });
  verifyDomain(domain: string): Promise<ValidationResult>;
  verifyBeacon(beacon: unknown): ValidationResult;
  verifyProof(proof: unknown): boolean;
}

// ============================================================
// Crypto Configuration
// ============================================================

export interface CryptoConfig {
  signatureAlgorithm: 'ML-DSA-65';
  kemAlgorithm: 'ML-KEM-768';
  hashAlgorithm: 'SHA3-256';
}

export declare const CRYPTO_CONFIG: CryptoConfig;

export declare function generateKeyPair(): KeyPair;
export declare function sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
export declare function verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean;
