interface BitGridProps {
  bytes: Uint8Array;
  /** When given, bits that differ from this same-length array are highlighted. */
  compareTo?: Uint8Array;
}

export function BitGrid({ bytes, compareTo }: BitGridProps) {
  return (
    <div className="flex flex-wrap gap-3" role="list" aria-label="Block bits">
      {Array.from(bytes).map((byte, byteIndex) => (
        <div key={byteIndex} role="listitem" className="flex gap-0.5">
          {Array.from({ length: 8 }, (_, bitOffset) => {
            const bit = (byte >> (7 - bitOffset)) & 1;
            const otherByte = compareTo?.[byteIndex] ?? byte;
            const otherBit = (otherByte >> (7 - bitOffset)) & 1;
            const changed = bit !== otherBit;
            return (
              <span
                key={bitOffset}
                title={`byte[${byteIndex}] bit ${7 - bitOffset}`}
                className={`flex size-5 items-center justify-center rounded-sm font-mono text-[11px] tabular-nums transition-colors duration-300 ${
                  changed ? 'bg-changed text-changed-foreground' : 'bg-panel text-muted-foreground ring-1 ring-inset ring-border'
                }`}
              >
                {bit}
              </span>
            );
          })}
        </div>
      ))}
    </div>
  );
}
