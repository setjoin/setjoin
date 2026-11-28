const BYTE_UNITS = [
    ['PB', 1024 ** 5],
    ['TB', 1024 ** 4],
    ['GB', 1024 ** 3],
    ['MB', 1024 ** 2],
    ['KB', 1024],
] as const;

/** Formats a byte count as a human-readable string (B -> PB). */
export function formatBytes(b: number): string {
    if (!b) return '0 B';
    for (const [unit, size] of BYTE_UNITS) {
        if (b >= size) return `${(b / size).toFixed(1)} ${unit}`;
    }
    return b + ' B';
}
