# NDK Documentation Analysis for Verity Integration

## Executive Summary

This document maps NDK documentation resources to Verity's specific integration needs. Verity is building a curated, private Nostr-based platform for the kink community with managed keys, custom serialization, and seamless NIP-46 signer integration. The analysis focuses on browser-side event caching, authentication workflows, and bunker/signer connectivity.

## High-Level Documentation Structure

Before diving into specific topics, understanding the NDK documentation organization helps navigate efficiently:

### Entry Points

1. **`./README.md`** - The root entry point
   - Complete package ecosystem map (core, frameworks, cache adapters, advanced features)
   - Quick start examples for Svelte 5, React, vanilla JS
   - NIP support matrix
   - **Purpose:** 10,000-foot view of what NDK offers

2. **`./docs/cookbook/index.md`** - Practical implementation patterns
   - Self-contained recipes with complete code examples
   - Categories: Authentication, Events, Relays, Payments, Testing, Mobile
   - Real-world patterns (multi-session management, NIP-46 bunker auth)
   - **Purpose:** Copy-paste ready patterns for common use cases

3. **`./core/docs/getting-started/introduction.md`** - Mental model establishment
   - Basic setup and debugging (browser + server)
   - Network debugging capabilities
   - **Purpose:** Getting NDK running and observable

### Core Concepts Documentation

4. **`./core/docs/tutorial/local-first.md`** - **Critical for Verity's static client**
   - **Optimistic publishing** pattern (fire-and-forget with cache)
   - **Offline-first** architecture with cache adapters
   - Handling persistent publish failures (`event:publish-failed`)
   - Automatic retry mechanism on app boot
   - **Purpose:** How NDK enables static client architecture with no backend

5. **`./core/docs/internals/subscriptions.md`** - Subscription lifecycle deep dive
   - Complete flow from `ndk.subscribe()` to `EVENT` responses
   - Outbox model relay selection (configurable `relayGoalPerAuthor`)
   - Subscription bundling and grouping algorithms
   - `at-least` vs `at-most` grouping delay strategies
   - Event handler patterns (`onEvent`, `onEvents`, `onEose`)
   - **Purpose:** Understanding NDK's intelligent subscription management

### Svelte 5 Integration

6. **`./svelte/INDEX.md`** - Documentation roadmap
   - Complete documentation overview (4,170 lines!)
   - Status: Design complete, implementation in progress
   - Reading guide for users, contributors, and migrators
   - **Purpose:** Navigation map for Svelte-specific docs

7. **`./svelte/API.md`** - Complete TypeScript API specifications
   - Detailed type definitions for all reactive stores
   - `EventSubscription<T>` interface with all reactive properties
   - Store APIs (profiles, sessions, mutes, wallet, payments)
   - Component prop interfaces (when implemented)
   - **Purpose:** **The contract** - what APIs will be available

### Why This Matters for Verity

**Local-First Pattern:** Verity's static client architecture aligns perfectly with NDK's local-first mode. The `./core/docs/tutorial/local-first.md` document is **essential** - it explains how to publish events optimistically to cache and handle offline scenarios.

**Subscription Efficiency:** The `./core/docs/internals/subscriptions.md` document reveals how NDK groups subscriptions intelligently. This is crucial for Verity's professional directory (fetching many profiles) - understanding grouping delays prevents unnecessary relay load.

**Svelte 5 Contract:** The `./svelte/API.md` is a **binding contract** for what the Svelte integration will provide. Even though implementation is in progress, this shows exactly what reactive APIs Verity can build against.

**Cookbook Patterns:** The cookbook provides production-ready patterns for:
- NIP-46 bunker authentication (matches Verity's hybrid auth flow)
- Multi-session management (useful for Phase 2+ if allowing linked identities)
- Testing with mock relays (critical for BDD testing infrastructure)

---

## Verity's Core Requirements

Based on the documentation reviewed:

1. **Private, curated Nostr network** with custom event serialization (kind 643)
2. **Managed key system** with seamless user experience (no manual key handling)
3. **Hybrid authentication**: Ory Kratos (web) + NIP-46 (signing) with pre-authorization event
4. **Browser-based client** using SvelteKit 5 with NDK for event management
5. **Event caching** in the browser for offline-first experience
6. **Custom Nostr events** for professional directory, credentials, and vouching

---

## 1. Core NDK Integration Documentation

### 1.1 Main README

**Location:** `./README.md`

**What it provides:**
- High-level overview of NDK architecture and philosophy
- Package ecosystem breakdown (core, framework integrations, advanced features, cache adapters)
- Quick start examples for Svelte 5, React, and vanilla JS
- NIP support matrix (critical: confirms NIP-46, NIP-44, NIP-07 support)

**Relevance to Verity:**
- ✅ **Confirms Svelte 5 first-class support** with reactive runes
- ✅ **Cache adapter options** for browser (Dexie, memory, SQLite WASM)
- ✅ **Session management package** for multi-account support
- ⚠️ **Note:** Examples assume public relay network - needs adaptation for private relay

**Key takeaway:** NDK is designed for exactly this use case, but all examples assume public Nostr. Verity will need to:
- Fork NDK to implement custom serialization
- Configure explicit private relay URLs only
- Disable outbox model/relay discovery features

---

### 1.2 Core Package README

**Location:** `./core/README.md`

**What it provides:**
- Installation and basic setup
- **AI Guardrails feature** for development (catches common mistakes)
- Event creation, validation, signing overview
- Signer adapter types (private key, NIP-07, NIP-46, NIP-49)

**Relevance to Verity:**
- ✅ **NIP-46 (nsecBunker) signer support** - core requirement
- ✅ **NIP-49 encrypted keys** - could be useful for managed key storage
- ✅ **Quick start template** showing NDK initialization pattern
- ⚠️ **Enable `aiGuardrails: true` during development** to catch integration errors

**Key takeaway:** Core package has everything needed for signer integration. The NIP-49 support could be valuable for securely storing managed keys in the browser before sending to bunker.

---

## 2. Browser-Side Caching Documentation

### 2.1 Cache Module System

**Location:** `./docs/cache-modules.md`

**What it provides:**
- **Extensible cache architecture** allowing packages to define custom schemas
- **Migration system** for schema versioning
- **TypeScript-first** with strong typing for collections
- **Adapter-agnostic** interface (Dexie, SQLite, Redis, etc.)
- **Module registration** pattern for separation of concerns

**Relevance to Verity:**
- ✅ **Essential for Verity's custom event types** (KAP profiles, credentials, vouches)
- ✅ **Schema versioning** will be critical as platform evolves through phases
- ✅ **Type safety** ensures correct data structure for custom events
- ✅ **Examples show message/conversation caching** - similar pattern for Verity's professional profiles

**Key takeaway:** This is the **primary mechanism** for caching custom Verity events (professional profiles, credentials, event registrations). Must use NDK's cache module system rather than custom IndexedDB code.

**Implementation pattern for Verity:**
```typescript
// Define Verity's cache module
export const verityCacheModule: CacheModuleDefinition = {
    namespace: 'verity',
    version: 1,
    collections: {
        kapProfiles: {
            primaryKey: 'pubkey',
            indexes: ['services', 'location', 'verificationStatus'],
            compoundIndexes: [['services', 'location']]
        },
        credentials: {
            primaryKey: 'id',
            indexes: ['issuer', 'recipient', 'credentialType', 'issuedAt']
        }
    },
    migrations: { /* ... */ }
};
```

---

### 2.2 Dexie Cache Adapter

**Location:** `./cache-dexie/README.md`

**What it provides:**
- **IndexedDB wrapper** using Dexie library
- **Browser-native persistence** (survives page reload)
- **Automatic cache-first strategy** then relay fallback
- **Production-ready** adapter for web apps

**Relevance to Verity:**
- ✅ **Primary cache adapter for Verity web-client**
- ✅ **Browser-only** (perfect for SvelteKit SPA mode)
- ✅ **Integrates with cache module system** for custom event schemas
- ⚠️ **Must configure with Verity database name** for isolation

**Key takeaway:** Use `NDKCacheAdapterDexie` as the primary cache adapter. Initialize with:
```typescript
const dexieAdapter = new NDKCacheAdapterDexie({ dbName: 'verity-app' });
await dexieAdapter.registerModule(verityCacheModule);
const ndk = new NDKSvelte({ cacheAdapter: dexieAdapter, /* ... */ });
```

---

### 2.3 Memory Cache Adapter

**Location:** `./cache-memory/README.md`

**What it provides:**
- **LRU cache** for fast in-memory storage
- **Synchronous queries** (no async overhead)
- **Configurable size limits** for events/profiles
- **Complete NDKCacheAdapter implementation**

**Relevance to Verity:**
- ✅ **Useful for testing/development** before Dexie integration
- ✅ **Fallback option** if IndexedDB unavailable
- ⚠️ **Not persistent** across page reloads
- ⚠️ **Less suitable for production** due to memory constraints

**Key takeaway:** Good for initial prototyping, but Dexie should be production cache. Could be useful as fallback if user's browser has IndexedDB disabled.

---

## 3. Authentication & Signer Integration

### 3.1 Signer Documentation

**Location:** `./core/docs/getting-started/signers.md`

**What it provides:**
- **NIP-07 (browser extension)** integration guide
- **NIP-46 (remote signer/bunker)** with two flows:
  - `bunker://` - User provides connection string
  - `nostrconnect://` - App generates QR code
- **NIP-49 (encrypted keys)** for secure storage
- **NDKPrivateKeySigner** for development/testing

**Relevance to Verity:**
- ✅️ **Critical for Verity's hybrid auth** (Ory Kratos + nsecbunkerd)
- ✅ **`bunker://` flow** - Verity will auto-generate this after Kratos login
- ✅ **`localNsec` persistence** - Verity can store this in localStorage for session continuity
- ⚠️ **Connection secret** - Verity's custom pre-auth event will replace standard bunker flow

**Key takeaway:** Verity's authentication flow will use a **modified NIP-46 bunker flow**:
1. User logs in via Ory Kratos (web auth)
2. Kratos hook publishes pre-auth event (kind 24164) with `session_secret`
3. Web client initializes `NDKNip46Signer` with:
   - Custom `bunker://` string pointing to nsecbunkerd
   - The `session_secret` from pre-auth event
   - Persistent `localNsec` from localStorage (for session persistence)

**Implementation pattern:**
```typescript
// After Kratos login, retrieve session_secret from pre-auth event
const preAuthEvent = await fetchPreAuthEvent(userId);
const sessionSecret = decryptSessionSecret(preAuthEvent);

// Initialize NIP-46 signer with secret
const bunkerUrl = 'bunker://verity-signer.local';
const localNsec = localStorage.getItem('verity_local_nsec');
const signer = NDKNip46Signer.bunker(ndk, bunkerUrl, localNsec);

// Authenticate using the pre-authorized secret
await signer.authenticateWithSecret(sessionSecret); // Custom method to add

// Store localNsec for future sessions
localStorage.setItem('verity_local_nsec', signer.localSigner.nsec);
```

---

### 3.2 Relay Authentication (NIP-42)

**Location:** `./core/docs/tutorial/auth.md`

**What it provides:**
- **Relay auth policies** for NIP-42 challenges
- **Built-in policies** (`signIn`, `disconnect`)
- **Custom policy functions** for user consent

**Relevance to Verity:**
- ✅ **Verity's private relay may require NIP-42 auth**
- ✅ **Can auto-authenticate** since user is already authenticated via Kratos
- ⚠️ **Should use `NDKRelayAuthPolicies.signIn`** by default

**Key takeaway:** Configure automatic NIP-42 authentication for Verity's private relay:
```typescript
ndk.relayAuthDefaultPolicy = NDKRelayAuthPolicies.signIn({ ndk });
```

---

## 4. Session Management

### 4.1 Sessions Package

**Location:** `./sessions/docs/index.md`

**What it provides:**
- **Multi-account support** with seamless switching
- **Automatic data fetching** (follows, mutes, relay lists, wallet)
- **Pluggable storage** (LocalStorage, FileStorage, Memory, Custom)
- **Framework-agnostic** core with Svelte/React bindings

**Relevance to Verity:**
- ⚠️ **May not be needed for MVP** - Verity uses managed keys, not multi-account
- ✅ **Auto-fetch features** (mutes, follows) could be useful for Phase 3 (web of trust)
- ⚠️ **LocalStorage persistence** - conflicts with Verity's managed key approach
- ❌ **Multi-account switching** - not a Verity use case

**Key takeaway:** The sessions package is designed for users managing their own keys across multiple accounts. Verity's managed key model means:
- Users don't switch Nostr accounts (they only have one, managed by platform)
- Session persistence is handled by Ory Kratos cookies, not NDK sessions
- Can skip `@nostr-dev-kit/sessions` package for MVP
- **Consider for Phase 2+** if allowing power users to link external Nostr identities

---

## 5. Svelte 5 Integration

### 5.1 Svelte Package

**Location:** `./svelte/README.md`

**What it provides:**
- **Runes-first reactive subscriptions** (`$state`, `$derived`, `$effect`)
- **`$subscribe()` method** with automatic cleanup
- **Namespaced stores** (`$sessions`, `$wot`, `$wallet`, `$payments`)
- **Reactive fetching** (`$fetchEvent`, `$fetchProfile`, `$fetchEvents`)
- **Buffered updates** for performance (30ms default)

**Relevance to Verity:**
- ✅ **Perfect fit for SvelteKit 5 architecture**
- ✅ **`$subscribe()` for reactive event feeds** (professional directory, credentials)
- ✅ **`$fetchProfile()` for user/professional profiles**
- ✅ **Built-in wallet integration** for future payment features
- ⚠️ **WoT auto-filter** - won't work with Verity's curated model (public Nostr WoT)

**Key takeaway:** Use `NDKSvelte` as the main NDK class. **Critical API note:**
```typescript
// ✅ CORRECT - callback function returning config
const notes = ndk.$subscribe(() => ({
  filters: [{ kinds: [KAP_PROFILE_KIND], limit: 50 }]
}));

// ❌ WRONG - direct config (doesn't exist)
const notes = ndk.$subscribe({ kinds: [1] });
```

**Implementation pattern for Verity:**
```typescript
// lib/ndk.ts
import { NDKSvelte } from '@nostr-dev-kit/svelte';
import NDKCacheAdapterDexie from '@nostr-dev-kit/cache-dexie';

export const ndk = new NDKSvelte({
  explicitRelayUrls: ['wss://relay.kinkaware.net'], // Private relay only
  cacheAdapter: new NDKCacheAdapterDexie({ dbName: 'verity-app' }),
  // Disable public Nostr features
  enableOutboxModel: false,
  autoConnectUserRelays: false,
  autoFetchUserMutelist: false
});

await ndk.connect();
```

**Reactive subscription in components:**
```svelte
<script lang="ts">
import { ndk } from '$lib/ndk';
import { VERITY_KINDS } from '$lib/constants';

// Reactive subscription to KAP profiles
const kapProfiles = ndk.$subscribe(() => ({
  filters: [{ kinds: [VERITY_KINDS.KAP_PROFILE], limit: 100 }]
}));

// Automatic reactivity - updates when new events arrive
$inspect(kapProfiles.events);
</script>

{#each kapProfiles.events as profile}
  <ProfileCard {profile} />
{/each}
```

---

## 6. Subscription & Event Management

### 6.1 Subscription Management

**Location:** `./core/docs/tutorial/subscription-management.md`

**What it provides:**
- **Automatic subscription grouping** to reduce relay load
- **Grouping delay configuration** (`at-least`, `at-most`)
- **Deferred subscriptions** with event handlers
- **Cache unconstrain filters** for flexible cache queries
- **Mute filtering** (automatic)

**Relevance to Verity:**
- ✅ **Grouping useful for professional directory** (fetching many profiles)
- ✅ **Mute filtering** - Verity needs this for content moderation
- ⚠️ **May need to disable grouping** for real-time credential issuance
- ✅ **Cache unconstrain** - good for loading all local profiles, but limited from relay

**Key takeaway:** Use subscription grouping for directory queries, disable for real-time event subscriptions:
```typescript
// Grouped subscription for directory (efficient)
const profiles = ndk.$subscribe(() => ({
  filters: [{ kinds: [KAP_PROFILE], limit: 100 }],
  opts: { groupable: true, groupingDelay: 100 }
}));

// Immediate subscription for credential notifications (real-time)
const credentials = ndk.$subscribe(() => ({
  filters: [{ kinds: [CREDENTIAL_KIND], '#p': [currentUser] }],
  opts: { groupable: false }
}));
```

---

### 6.2 Publishing Events

**Location:** `./core/docs/tutorial/publishing.md`

**What it provides:**
- **Replaceable event handling** with `publishReplaceable()`
- **Optimistic publish lifecycle** (local-first)
- **Event kind ranges** (0, 3, 10000-19999, 30000-39999)

**Relevance to Verity:**
- ✅ **Verity's KAP profiles are replaceable** (kind ranges to be determined)
- ✅ **Credential issuing** needs proper replaceable event handling
- ✅ **`publishReplaceable()` prevents stale events**

**Key takeaway:** Use `publishReplaceable()` for profile updates:
```typescript
// Update KAP profile
const profile = await ndk.fetchEvent({ kinds: [KAP_PROFILE], authors: [userPubkey] });
profile.tags.push(['service', 'Consent Education']);
await profile.publishReplaceable(); // ✅ Correct - updates created_at
// NOT: await profile.publish(); // ❌ Wrong - relay will reject stale event
```

---

### 6.3 Event Class Registration

**Location:** `./core/docs/event-class-registration.md`

**What it provides:**
- **Custom event class system** via `registerEventClass()`
- **Static `kinds` property** for event kind mapping
- **Static `from()` factory** for event wrapping
- **Integration with `wrapEvent()`**

**Relevance to Verity:**
- ✅ **Essential for Verity's custom event types**
- ✅ **Type-safe event handling** for KAP profiles, credentials, vouches
- ✅ **Clean abstraction** for event-specific logic

**Key takeaway:** Define custom event classes for all Verity event types:
```typescript
// lib/events/KAPProfile.ts
import { NDKEvent, registerEventClass } from '@nostr-dev-kit/ndk';

export class KAPProfile extends NDKEvent {
    static kinds = [VERITY_KINDS.KAP_PROFILE];
    
    static from(event: NDKEvent) {
        return new KAPProfile(event.ndk, event);
    }
    
    constructor(ndk: NDK | undefined, rawEvent?: NostrEvent) {
        super(ndk, rawEvent);
        this.kind ??= VERITY_KINDS.KAP_PROFILE;
    }
    
    get displayName(): string | undefined {
        return this.tagValue('name');
    }
    
    get services(): string[] {
        return this.getMatchingTags('service').map(t => t[1]);
    }
    
    get isVerified(): boolean {
        return this.tagValue('verified') === 'true';
    }
}

// Register globally
registerEventClass(KAPProfile);
```

---

## 7. Local-First Development (Critical for Verity)

### 7.1 Local-First Philosophy

**Location:** `./core/docs/tutorial/local-first.md`

**What it provides:**
- **Optimistic publishing** pattern - fire-and-forget event creation
- **Cache-first architecture** - events written to cache immediately
- **Automatic retries** - failed events automatically retried on app restart
- **Failure handling** - `event:publish-failed` event for UI notifications
- **Unpublished event tracking** - query and manually retry failed publishes

**Relevance to Verity:**
- ✅ **Perfect for static SvelteKit SPA** - no backend server needed
- ✅ **Offline-first UX** - users can create content offline
- ✅ **Reliable event publishing** - automatic retries handle network issues
- ✅ **Cache adapters enable this** - Dexie supports unpublished event tracking

**Key takeaway:** Verity's static client architecture is **explicitly supported** by NDK. The local-first mode is not a hack or workaround - it's a first-class usage pattern.

**Two publishing modes:**

1. **Blocked Publishing** (await confirmation):
```typescript
const event = new NDKEvent(ndk, { kind: 1, content: 'Important update' });
const publishedToRelays = await event.publish(); // Waits for confirmation
console.log(`Published to ${publishedToRelays.size} relays`);
```

2. **Optimistic Publishing** (fire-and-forget):
```typescript
const event = new NDKEvent(ndk, { kind: 1, content: 'Quick note' });
event.publish(); // Returns immediately
// Event written to cache first, then published to relays in background
```

**Implementation pattern for Verity:**
```typescript
// Global error handler for publish failures
ndk.on("event:publish-failed", (event: NDKEvent, error: NDKPublishError) => {
  console.error(`Event ${event.id} failed to publish`, {
    publishedToRelays: error.publishedToRelays,
    failedRelays: error.failedRelays
  });
  
  // Show user notification
  toastStore.error(`Failed to publish ${event.kind === KAP_PROFILE ? 'profile' : 'event'}`);
});

// On app boot, retry failed events
const failedEvents = await ndk.cacheAdapter.getUnpublishedEvents();
if (failedEvents.length > 0) {
  console.log(`Retrying ${failedEvents.length} failed events`);
  failedEvents.forEach(event => event.publish());
}

// Profile updates use optimistic publishing
async function updateProfile(updates: Partial<KAPProfile>) {
  const event = createProfileEvent(updates);
  event.publish(); // Fire-and-forget
  
  // UI updates immediately from cache
  // No need to wait for relay confirmation
}
```

**Critical for Verity:**
- **KAP profile updates** should use optimistic publishing for instant UI feedback
- **Credential issuance** may want blocked publishing to ensure delivery
- **Event registration** depends on business logic - instant UX vs guaranteed delivery

---

### 7.2 Subscription Lifecycle Internals

**Location:** `./core/docs/internals/subscriptions.md`

**What it provides:**
- **Complete subscription flow** with detailed flowcharts
- **Relay selection** via outbox model (configurable with `relayGoalPerAuthor`)
- **Subscription bundling** - how NDK groups similar subscriptions
- **Grouping delays** - `at-least` vs `at-most` strategies
- **Event distribution** - how events route from relays to subscriptions
- **Bulk cache handling** - `onEvents` callback for initial cache load

**Relevance to Verity:**
- ✅ **Understand relay selection** for single private relay configuration
- ✅ **Grouping delays optimization** for directory performance
- ✅ **Cache event handling** for instant UI from IndexedDB
- ⚠️ **Outbox model must be disabled** (Verity uses single relay)

**Key takeaway:** NDK's subscription system is **highly optimized** but designed for public Nostr's multi-relay environment. Verity needs to **disable certain features** (outbox model, relay discovery) but can leverage grouping and caching.

**Relay selection behavior:**
- Default: 2 relays per author via outbox model
- Configurable: `relayGoalPerAuthor: 3` or `Infinity`
- Problem for Verity: This assumes multiple relays per author
- **Solution:** Configure with single explicit relay, disable outbox

**Grouping delay strategies:**

```typescript
// at-least: Timer resets on each new subscription
// If two subs arrive 50ms apart with 200ms delay, executes at t=250ms
const sub1 = ndk.subscribe(filters, {
  groupingDelay: 200,
  groupingDelayType: "at-least"
});

// at-most: Timer doesn't reset
// Executes at t=200ms regardless of later subscriptions
const sub2 = ndk.subscribe(filters, {
  groupingDelay: 200,
  groupingDelayType: "at-most"
});
```

**Event handler patterns:**

```typescript
// Pattern 1: Individual event handling
ndk.subscribe(filters, {}, {
  onEvent: (event) => {
    console.log('Event:', event.id);
  },
  onEose: () => {
    console.log('EOSE reached');
  }
});

// Pattern 2: Bulk cache handling (prevents UI thrashing)
ndk.subscribe(filters, {}, {
  // Called ONCE with all cached events
  onEvents: (events) => {
    console.log(`Loaded ${events.length} from cache`);
    // Batch UI update
    updateUIBatch(events);
  },
  // Called for each new relay event
  onEvent: (event) => {
    console.log('New relay event:', event.id);
    updateUISingle(event);
  }
});
```

**Implementation pattern for Verity directory:**
```typescript
// Professional directory subscription with optimized grouping
const kapProfiles = ndk.$subscribe(() => ({
  filters: [{ kinds: [KAP_PROFILE], limit: 100 }],
  opts: {
    // Use at-most to ensure timely execution
    groupingDelay: 100,
    groupingDelayType: "at-most",
    
    // Disable expensive features for private relay
    groupable: true, // Keep grouping for efficiency
    
    // Handle initial cache load efficiently
    onEvents: (cachedProfiles) => {
      // Batch render 100 profiles at once
      console.log(`Loaded ${cachedProfiles.length} profiles from cache`);
    },
    
    // Stream in new profiles from relay
    onEvent: (profile) => {
      console.log('New profile from relay:', profile.pubkey);
    }
  }
}));
```

**For Verity's single relay:**
```typescript
// Configure NDK to skip outbox model
const ndk = new NDKSvelte({
  explicitRelayUrls: ['wss://relay.kinkaware.net'],
  enableOutboxModel: false, // Critical: disable multi-relay selection
  autoConnectUserRelays: false, // Don't use NIP-65 relay lists
  // ... other config
});
```

---

### 7.3 Cookbook Patterns

**Location:** `./docs/cookbook/index.md`

**What it provides:**
- **Production-ready code examples** organized by category
- **Authentication recipes** (NIP-07, NIP-46 bunker, multi-session)
- **Testing recipes** (mock relays for unit tests)
- **Payment recipes** (NWC, Cashu wallets)
- **Self-contained examples** with complete implementations

**Relevance to Verity:**
- ✅ **NIP-46 authentication pattern** - matches Verity's bunker flow
- ✅ **Mock relay testing** - critical for BDD test infrastructure
- ⚠️ **Multi-session management** - not needed for MVP (managed keys)
- ⚠️ **Payment integrations** - useful for Phase 3 (event fees, credentials marketplace)

**Key recipes for Verity:**

1. **Complete Authentication Flow with NIP-46** (`./docs/cookbook/svelte5/basic-authentication.md`)
   - Supports browser extensions (NIP-07), private keys (nsec), and remote signers (NIP-46)
   - Includes `bunker://` and `nostrconnect://` flows
   - QR code generation for mobile signers
   - Error handling patterns

2. **Testing with Mock Relays** (`./docs/cookbook/testing/mock-relays.md`)
   - Create mock relays for unit tests
   - No real relay connections needed
   - Perfect for BDD test harness with isolated relays per scenario

**Key takeaway:** The cookbook contains **battle-tested patterns**. Rather than implementing NIP-46 from scratch, Verity can adapt the cookbook's bunker authentication recipe by adding the pre-authorization event flow.

**Example adaptation for Verity:**
```typescript
// Cookbook pattern (standard NIP-46 bunker)
const signer = NDKNip46Signer.bunker(ndk, bunkerUrl, localNsec);
await signer.blockUntilReady();

// Verity adaptation (with pre-auth event)
const preAuthEvent = await fetchPreAuthEventFromRelay(userKratosId);
const sessionSecret = decryptSessionSecret(preAuthEvent);

const signer = NDKNip46Signer.bunker(ndk, bunkerUrl, localNsec);

// Custom method to add: authenticate with pre-authorized secret
await signer.authenticateWithSecret(sessionSecret);

// Store localNsec for session persistence
localStorage.setItem('verity_local_nsec', signer.localSigner.nsec);
```

---

## 8. Architecture & Best Practices

### 7.1 Custom Serialization Implementation

**Location:** `./core/src/events/serializer.ts` (code inspection needed)

**What to modify:**
- Fork NDK and create `VerityEvent.ts` using monkey-patch pattern
- Replace `serialize()` method to use kind 643 instead of 0
- Update event ID calculation to match custom format

**Implementation approach:**
```typescript
// event-protocol-module/core/src/events/VerityEvent.ts
import * as NDK from '@nostr-dev-kit/ndk';

const { NDKEvent } = NDK;

function veritySerialize(this: NDK.NDKEvent): string {
    validateForSerialization(this);
    
    // Verity custom format: [643, pubkey, created_at, kind, tags, content]
    const payload = [643, this.pubkey, this.created_at, this.kind, this.tags, this.content];
    if (this.sig) payload.push(this.sig);
    if (this.id) payload.push(this.id);
    
    return JSON.stringify(payload);
}

// Monkey-patch the prototype
NDKEvent.prototype.serialize = veritySerialize;

// Re-export everything
export * from '@nostr-dev-kit/ndk';
```

**Critical:** This must be done **before** any NDK usage in the application. Import from this file instead of original NDK:
```typescript
// Use this everywhere instead of @nostr-dev-kit/ndk
import { NDK, NDKEvent } from '$lib/verity-ndk';
```

---

## 8. Documentation Gaps & Questions

### 8.1 Missing Documentation for Verity

1. **Custom serialization with NIP-46**: No examples of modifying event serialization while maintaining NIP-46 compatibility
2. **Private relay configurations**: All examples assume public Nostr network
3. **Disabling outbox model**: No clear guide on fully isolating NDK to single relay
4. **Pre-authorization patterns**: No examples of custom auth flows before NIP-46 connection

### 8.2 Questions for NDK Community

1. **Does NIP-46 signer need to support custom serialization?** If web client uses kind 643, does nsecbunkerd also need modification?
2. **Impact of custom serialization on relay auth?** Will NIP-42 AUTH events work with modified serialization?
3. **Cache module compatibility**: Do cache modules work with custom event kinds outside standard Nostr ranges?

---

## 9. Recommended Documentation Reading Order

For effective Verity integration, read in this order:

### Phase 1: Foundation & Mental Model (Week 1)

**Goal:** Understand what NDK is, how it works, and why it fits Verity's architecture

1. **`./README.md`** - Start here for the big picture
   - Purpose: Understand the NDK ecosystem (core, frameworks, cache adapters)
   - Time: 20 minutes
   - Key takeaway: NDK is modular - we only use what we need

2. **`./core/docs/getting-started/introduction.md`** - Basic setup
   - Purpose: Learn how to initialize NDK and enable debugging
   - Time: 10 minutes
   - Key takeaway: `localStorage.debug = 'ndk:*'` for browser debugging

3. **`./core/README.md`** - Core concepts
   - Purpose: Understand event creation, validation, and signing
   - Time: 15 minutes
   - Key takeaway: Enable `aiGuardrails: true` during development

4. **`./core/docs/tutorial/local-first.md`** - **CRITICAL FOR VERITY**
   - Purpose: **How NDK enables static client architecture**
   - Time: 30 minutes
   - Key takeaway: Optimistic publishing + cache = offline-first SPA

### Phase 2: Caching & Events (Week 1-2)

**Goal:** Implement browser-side event caching for custom Verity events

5. **`./docs/cache-modules.md`** - Cache architecture
   - Purpose: Learn how to extend cache adapters with custom schemas
   - Time: 45 minutes
   - Key takeaway: Define cache modules for KAP profiles, credentials, etc.

6. **`./cache-dexie/README.md`** - Browser cache implementation
   - Purpose: Understand Dexie (IndexedDB) configuration
   - Time: 10 minutes
   - Key takeaway: `new NDKCacheAdapterDexie({ dbName: 'verity-app' })`

7. **`./core/docs/event-class-registration.md`** - Custom event types
   - Purpose: Create type-safe classes for Verity events
   - Time: 30 minutes
   - Key takeaway: `registerEventClass(KAPProfile)` for custom events

8. **`./core/docs/tutorial/publishing.md`** - Event publishing
   - Purpose: Understand replaceable events and `publishReplaceable()`
   - Time: 15 minutes
   - Key takeaway: Profile updates need `publishReplaceable()`, not `publish()`

### Phase 3: Subscriptions & Performance (Week 2)

**Goal:** Optimize event fetching for professional directory and real-time updates

9. **`./core/docs/internals/subscriptions.md`** - **Subscription deep dive**
   - Purpose: Understand grouping, bundling, and relay selection
   - Time: 60 minutes
   - Key takeaway: Disable outbox model, use `at-most` grouping for directory

10. **`./core/docs/tutorial/subscription-management.md`** - Subscription API
    - Purpose: Learn grouping options and mute filtering
    - Time: 20 minutes
    - Key takeaway: `groupingDelayType: "at-most"` for responsive UX

### Phase 4: Svelte 5 Integration (Week 2-3)

**Goal:** Implement reactive UI with NDK's Svelte 5 integration

11. **`./svelte/INDEX.md`** - Documentation roadmap
    - Purpose: Navigate the Svelte-specific documentation
    - Time: 15 minutes
    - Key takeaway: 4,170 lines of design docs available

12. **`./svelte/API.md`** - **TypeScript API contract**
    - Purpose: Reference for all reactive store APIs
    - Time: 45 minutes (reference, not linear reading)
    - Key takeaway: `EventSubscription<T>` interface, store types

13. **`./svelte/README.md`** - Svelte 5 patterns
    - Purpose: Learn reactive subscription patterns with runes
    - Time: 40 minutes
    - Key takeaway: `const notes = ndk.$subscribe(() => ({ filters: [...] }))`

### Phase 5: Authentication & Signers (Week 3)

**Goal:** Implement hybrid Kratos + NIP-46 bunker authentication

14. **`./core/docs/getting-started/signers.md`** - **Signer types**
    - Purpose: Understand NIP-46 bunker flow (`bunker://` protocol)
    - Time: 30 minutes
    - Key takeaway: `NDKNip46Signer.bunker()` with `localNsec` persistence

15. **`./docs/cookbook/svelte5/basic-authentication.md`** - Production pattern
    - Purpose: Copy-paste ready authentication flow
    - Time: 20 minutes
    - Key takeaway: Adapt cookbook pattern with Verity's pre-auth event

16. **`./core/docs/tutorial/auth.md`** - Relay authentication
    - Purpose: Configure NIP-42 auto-authentication
    - Time: 10 minutes
    - Key takeaway: `NDKRelayAuthPolicies.signIn({ ndk })`

### Phase 6: Testing & Cookbook (Week 3-4)

**Goal:** Implement BDD test infrastructure and learn production patterns

17. **`./docs/cookbook/testing/mock-relays.md`** - Mock relays for tests
    - Purpose: Create isolated relay environment for BDD tests
    - Time: 25 minutes
    - Key takeaway: TestContainer-style isolated relays per scenario

18. **`./docs/cookbook/index.md`** - Browse recipes
    - Purpose: Learn production patterns by category
    - Time: 30 minutes (browsing)
    - Key takeaway: Copy-paste ready solutions for common problems

### Optional (Future Phases)

19. **`./sessions/docs/index.md`** - Session management (Phase 2+)
    - When: If allowing users to link external Nostr identities
    - Time: 25 minutes
    - Relevance: Multi-account support (not needed for managed keys MVP)

20. **`./wot/README.md`** - Web of Trust (Phase 3)
    - When: Implementing reputation system and vouching
    - Time: 30 minutes
    - Relevance: Community-led curation and trust networks

21. **`./wallet/README.md`** - Payment integration (Phase 3+)
    - When: Adding event fees, credential marketplace, tips
    - Time: 35 minutes
    - Relevance: Cashu/NWC wallet integration for payments

---

## 10. Integration Checklist

### Must Read Before Development
- [ ] `./README.md` - Overall architecture
- [ ] `./core/docs/getting-started/signers.md` - NIP-46 bunker flow
- [ ] `./svelte/README.md` - Reactive subscription API
- [ ] `./docs/cache-modules.md` - Custom event caching

### Must Implement for MVP
- [ ] Fork NDK with custom serialization (VerityEvent.ts)
- [ ] Configure NDKSvelte with Dexie cache adapter
- [ ] Register Verity cache module for custom events
- [ ] Create custom event classes (KAPProfile, Credential, etc.)
- [ ] Implement modified NIP-46 flow with pre-auth event
- [ ] Configure private relay with explicit URL (disable discovery)

### Nice to Have for MVP
- [ ] Implement mute filtering for moderation
- [ ] Set up NIP-42 auto-authentication
- [ ] Configure subscription grouping for performance
- [ ] Add event class validation in cache modules

### Future Phases (2-3)
- [ ] Review `./sessions/docs/index.md` for multi-identity support
- [ ] Review `./wot/README.md` for web of trust features
- [ ] Consider `./wallet/README.md` for payment integration

---

## 11. Key Files Reference

| Concern | File Path | Priority | Time |
|---------|-----------|----------|------|
| **High-Level Overview** | `./README.md` | 🔴 Critical | 20min |
| **Debugging Setup** | `./core/docs/getting-started/introduction.md` | 🔴 Critical | 10min |
| **Local-First Architecture** | `./core/docs/tutorial/local-first.md` | 🔴 Critical | 30min |
| **Subscription Internals** | `./core/docs/internals/subscriptions.md` | 🔴 Critical | 60min |
| **Svelte API Contract** | `./svelte/API.md` | 🔴 Critical | 45min |
| **Svelte Documentation Map** | `./svelte/INDEX.md` | 🔴 Critical | 15min |
| **Core Setup & Signers** | `./core/README.md` | 🔴 Critical | 15min |
| **NIP-46 Bunker Auth** | `./core/docs/getting-started/signers.md` | 🔴 Critical | 30min |
| **Svelte 5 Integration** | `./svelte/README.md` | 🔴 Critical | 40min |
| **Custom Event Caching** | `./docs/cache-modules.md` | 🔴 Critical | 45min |
| **Dexie Cache (Browser)** | `./cache-dexie/README.md` | 🔴 Critical | 10min |
| **Cookbook Recipes** | `./docs/cookbook/index.md` | 🟡 High | 30min |
| **NIP-46 Recipe** | `./docs/cookbook/svelte5/basic-authentication.md` | 🟡 High | 20min |
| **Mock Relay Testing** | `./docs/cookbook/testing/mock-relays.md` | 🟡 High | 25min |
| **Custom Event Classes** | `./core/docs/event-class-registration.md` | 🟡 High | 30min |
| **Publishing Events** | `./core/docs/tutorial/publishing.md` | 🟡 High | 15min |
| **Subscription Management** | `./core/docs/tutorial/subscription-management.md` | 🟡 High | 20min |
| **Relay Auth (NIP-42)** | `./core/docs/tutorial/auth.md` | 🟢 Medium | 10min |
| **Session Management** | `./sessions/docs/index.md` | ⚪ Low (Phase 2+) | 25min |
| **Memory Cache (Fallback)** | `./cache-memory/README.md` | ⚪ Low (Testing) | 10min |

**Total critical reading time:** ~5.5 hours  
**Total high priority time:** ~2.5 hours  
**Total for MVP:** ~8 hours of focused documentation reading

---

## 12. Summary

### What NDK Provides for Verity

✅ **Perfect Fit:**
- Svelte 5 reactive integration with runes
- Browser-side caching with Dexie (IndexedDB)
- Custom event type system with TypeScript safety
- NIP-46 remote signer support
- Extensible cache module architecture
- Subscription management with grouping

⚠️ **Needs Modification:**
- Custom event serialization (kind 643) - requires NDK fork
- Private relay isolation (disable outbox model/discovery)
- Pre-authorization flow for bunker connection

❌ **Not Applicable:**
- Session management package (managed keys, not multi-account)
- Web of Trust auto-filter (public Nostr WoT doesn't apply to curated network)
- Relay discovery (single private relay)

### Primary Documentation Dependencies

**Critical Path:**
1. Fork NDK → Implement custom serialization → Test with local relay
2. Review Svelte integration docs → Set up NDKSvelte with Dexie cache
3. Design Verity event schemas → Create cache modules → Register event classes
4. Review NIP-46 docs → Implement pre-auth flow → Test bunker connection

**Estimated Reading Time:** 8-12 hours for critical documentation
**Estimated Implementation Time:** 2-3 weeks for core NDK integration (MVP)
