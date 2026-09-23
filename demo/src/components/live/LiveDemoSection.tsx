import { useState, type ReactNode } from 'react';
import { encrypt, decrypt, DEFAULT_ROUNDS, MIN_ROUNDS, MAX_ROUNDS } from '@cipher/algorithm';
import { Panel } from '../shared/Panel';
import { Badge } from '../shared/Badge';
import { Button } from '../shared/Button';
import { IconLock, IconUnlock, IconKey, IconEye, IconCheck, IconAlert, IconCopy } from '../../icons/icons';

export function LiveDemoSection() {
  const [plaintext, setPlaintext] = useState('Meet me at midnight.');
  const [key, setKey] = useState('correct horse battery staple');
  const [rounds, setRounds] = useState(DEFAULT_ROUNDS);

  const [ivHex, setIvHex] = useState('');
  const [ciphertextHex, setCiphertextHex] = useState('');
  const [encryptError, setEncryptError] = useState<string | null>(null);

  const [decrypted, setDecrypted] = useState<string | null>(null);
  const [decryptError, setDecryptError] = useState<string | null>(null);

  function handleEncrypt() {
    setDecrypted(null);
    setDecryptError(null);
    try {
      const result = encrypt(plaintext, key, { rounds });
      setIvHex(result.ivHex);
      setCiphertextHex(result.ciphertextHex);
      setEncryptError(null);
    } catch (err) {
      setEncryptError((err as Error).message);
    }
  }

  function handleDecrypt() {
    setDecryptError(null);
    try {
      const combinedHex = ivHex + ciphertextHex;
      setDecrypted(decrypt(combinedHex, key, { rounds }));
    } catch (err) {
      setDecrypted(null);
      setDecryptError((err as Error).message);
    }
  }

  const matchesOriginal = decrypted !== null && decrypted === plaintext;

  return (
    <div className="flex flex-col gap-6">
      <div className="max-w-3xl">
        <h2 className="font-display text-2xl font-semibold tracking-tight text-foreground">Live encrypt &amp; decrypt</h2>
        <p className="mt-2 text-base text-muted-foreground">
          Encrypt a message, inspect the ciphertext and IV, then decrypt it back — proving{' '}
          <code className="font-mono text-sm text-foreground">decrypt(encrypt(m, key), key) === m</code> live.
        </p>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <Panel title="Plaintext & key" icon={<IconLock className="size-5" />}>
          <div className="flex flex-col gap-4">
            <Field label="Plaintext">
              <textarea
                value={plaintext}
                onChange={(e) => setPlaintext(e.target.value)}
                rows={3}
                className="w-full resize-none rounded-lg bg-panel px-3 py-2 font-mono text-sm text-foreground ring-1 ring-inset ring-border focus:outline-2 focus:outline-offset-2 focus:outline-ring"
              />
            </Field>

            <Field label="Key" icon={<IconKey className="size-4" />}>
              <input
                type="text"
                value={key}
                onChange={(e) => setKey(e.target.value)}
                className="w-full rounded-lg bg-panel px-3 py-2 font-mono text-sm text-foreground ring-1 ring-inset ring-border focus:outline-2 focus:outline-offset-2 focus:outline-ring"
              />
            </Field>

            <Field label="Rounds">
              <div className="flex items-center gap-3">
                <input
                  type="range"
                  min={MIN_ROUNDS}
                  max={MAX_ROUNDS}
                  value={rounds}
                  onChange={(e) => setRounds(Number(e.target.value))}
                  className="h-2 w-40 cursor-pointer accent-diffusion"
                />
                <span className="font-mono text-sm text-foreground">{rounds}</span>
              </div>
            </Field>

            {encryptError && <ErrorNote message={encryptError} />}

            <Button icon={<IconLock className="size-4" />} onClick={handleEncrypt}>
              Encrypt
            </Button>
          </div>
        </Panel>

        <Panel title="Ciphertext" icon={<IconEye className="size-5" />} description="IV and ciphertext are not secret — inspect or edit them freely">
          <div className="flex flex-col gap-4">
            <Field label="IV (hex)" badge={<Badge tone="public">public</Badge>}>
              <HexField value={ivHex} onChange={setIvHex} placeholder="Encrypt to generate an IV" />
            </Field>

            <Field label="Ciphertext (hex)" badge={<Badge tone="public">public</Badge>}>
              <HexField value={ciphertextHex} onChange={setCiphertextHex} placeholder="Encrypt to generate ciphertext" rows={3} />
            </Field>

            {decryptError && <ErrorNote message={decryptError} />}

            <Button icon={<IconUnlock className="size-4" />} variant="secondary" onClick={handleDecrypt} disabled={!ivHex || !ciphertextHex}>
              Decrypt
            </Button>

            {decrypted !== null && (
              <div
                className={`rounded-lg p-4 ring-1 ring-inset ${
                  matchesOriginal ? 'bg-accent/10 ring-accent/40' : 'bg-destructive/10 ring-destructive/40'
                }`}
              >
                <div className="flex items-center gap-2">
                  {matchesOriginal ? <IconCheck className="size-4 text-accent" /> : <IconAlert className="size-4 text-destructive" />}
                  <span className={`font-display text-xs font-semibold tracking-wide uppercase ${matchesOriginal ? 'text-accent' : 'text-destructive'}`}>
                    {matchesOriginal ? 'Matches original plaintext' : 'Does not match original plaintext'}
                  </span>
                </div>
                <p className="mt-2 font-mono text-sm break-words text-foreground">{decrypted || '—'}</p>
              </div>
            )}
          </div>
        </Panel>
      </div>
    </div>
  );
}

function Field({ label, icon, badge, children }: { label: string; icon?: ReactNode; badge?: ReactNode; children: ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1.5 flex items-center gap-1.5 font-display text-xs font-medium tracking-wide text-muted-foreground uppercase">
        {icon}
        {label}
        {badge}
      </span>
      {children}
    </label>
  );
}

function HexField({ value, onChange, placeholder, rows }: { value: string; onChange: (v: string) => void; placeholder?: string; rows?: number }) {
  const [copied, setCopied] = useState(false);

  async function handleCopy() {
    if (!value) return;
    await navigator.clipboard.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 1200);
  }

  return (
    <div className="relative">
      <textarea
        value={value}
        onChange={(e) => onChange(e.target.value.trim())}
        placeholder={placeholder}
        rows={rows ?? 1}
        className="w-full resize-none rounded-lg bg-panel px-3 py-2 pr-10 font-mono text-sm text-diffusion ring-1 ring-inset ring-border placeholder:text-muted-foreground focus:outline-2 focus:outline-offset-2 focus:outline-ring"
      />
      <button
        type="button"
        onClick={handleCopy}
        aria-label="Copy to clipboard"
        className="absolute top-2 right-2 cursor-pointer rounded-md p-1.5 text-muted-foreground hover:bg-muted hover:text-foreground"
      >
        {copied ? <IconCheck className="size-4 text-accent" /> : <IconCopy className="size-4" />}
      </button>
    </div>
  );
}

function ErrorNote({ message }: { message: string }) {
  return (
    <div className="flex items-start gap-2 rounded-lg bg-destructive/10 p-3 text-sm text-red-300 ring-1 ring-inset ring-destructive/40">
      <IconAlert className="mt-0.5 size-4 shrink-0" />
      <span>{message}</span>
    </div>
  );
}
