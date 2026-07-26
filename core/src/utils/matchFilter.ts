import type { NostrEvent } from "../events/index.js";
import type { NDKFilter } from "../subscription/index.js";

/**
 * Checks if a single NDKFilter matches a NostrEvent.
 */
export function matchFilter(filter: NDKFilter, event: NostrEvent): boolean {
    if (filter.ids && filter.ids.indexOf(event.id as string) === -1) return false;
    if (filter.kinds && filter.kinds.indexOf(event.kind) === -1) return false;
    if (filter.authors && filter.authors.indexOf(event.pubkey) === -1) return false;

    for (const f in filter) {
        if (f[0] === '#') {
            const tagName = f.slice(1);
            const match = filter[f as keyof NDKFilter] as string[] | undefined;
            if (match && (!event.tags || !event.tags.find((t) => t[0] === tagName && match.indexOf(t[1]) !== -1))) return false;
        }
    }

    if (filter.since && event.created_at < filter.since) return false;
    if (filter.until && event.created_at > filter.until) return false;

    return true;
}

/**
 * Checks if any of the provided NDKFilters matches a NostrEvent.
 */
export function matchFilters(filters: NDKFilter[], event: NostrEvent): boolean {
    for (let i = 0; i < filters.length; i++) {
        if (matchFilter(filters[i], event)) return true;
    }
    return false;
}
