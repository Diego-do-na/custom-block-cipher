type ByteFormat = 'hex' | 'bin';

interface ByteGridProps {
  bytes: Uint8Array;
  /** When given, bytes that differ from this same-length array are highlighted. */
  compareTo?: Uint8Array;
  format?: ByteFormat;
  size?: 'sm' | 'md';
  highlightClassName?: string;
}

function formatByte(value: number, format: ByteFormat): string {
  return format === 'hex' ? value.toString(16).padStart(2, '0') : value.toString(2).padStart(8, '0');
}

export function ByteGrid({ bytes, compareTo, format = 'hex', size = 'md', highlightClassName = 'bg-changed/20 text-changed ring-changed/60' }: ByteGridProps) {
  const cellSize = size === 'sm' ? 'min-w-9 px-1.5 py-1 text-xs' : 'min-w-12 px-2 py-1.5 text-sm';

  return (
    <div className="flex flex-wrap gap-1.5" role="list" aria-label="Block bytes">
      {Array.from(bytes).map((value, index) => {
        const changed = compareTo ? compareTo[index] !== value : false;
        return (
          <span
            key={index}
            role="listitem"
            title={`byte[${index}] = 0x${value.toString(16).padStart(2, '0')} (${value})`}
            className={`font-mono ${cellSize} rounded-md text-center tabular-nums ring-1 ring-inset transition-colors duration-300 ${
              changed ? highlightClassName : 'bg-panel text-foreground ring-border'
            }`}
          >
            {formatByte(value, format)}
          </span>
        );
      })}
    </div>
  );
}
