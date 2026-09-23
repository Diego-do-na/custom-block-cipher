/**
 * Hand-drawn SVG icon set for this demo (no emoji, per project constraints).
 * Minimal, consistent 1.5px stroke line icons in the Lucide/Heroicons style.
 */
import type { ReactNode, SVGProps } from 'react';

type IconProps = SVGProps<SVGSVGElement>;

function base(children: ReactNode, props: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.75}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      {...props}
    >
      {children}
    </svg>
  );
}

export const IconBook = (props: IconProps) =>
  base(
    <>
      <path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20" />
      <path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2Z" />
    </>,
    props,
  );

export const IconPlay = (props: IconProps) =>
  base(<path d="M7 4.5v15l13-7.5-13-7.5Z" strokeLinejoin="round" />, props);

export const IconLayers = (props: IconProps) =>
  base(
    <>
      <path d="m12 2 9 5-9 5-9-5 9-5Z" />
      <path d="m3 12 9 5 9-5" />
      <path d="m3 17 9 5 9-5" />
    </>,
    props,
  );

export const IconWaves = (props: IconProps) =>
  base(
    <>
      <path d="M2 8c1.5-2 3.5-2 5 0s3.5 2 5 0 3.5-2 5 0 3.5 2 5 0" />
      <path d="M2 14c1.5-2 3.5-2 5 0s3.5 2 5 0 3.5-2 5 0 3.5 2 5 0" />
      <path d="M2 20c1.5-2 3.5-2 5 0s3.5 2 5 0 3.5-2 5 0 3.5 2 5 0" />
    </>,
    props,
  );

export const IconLock = (props: IconProps) =>
  base(
    <>
      <rect x="4" y="10.5" width="16" height="10" rx="2" />
      <path d="M7.5 10.5V7a4.5 4.5 0 0 1 9 0v3.5" />
    </>,
    props,
  );

export const IconUnlock = (props: IconProps) =>
  base(
    <>
      <rect x="4" y="10.5" width="16" height="10" rx="2" />
      <path d="M7.5 10.5V7a4.5 4.5 0 0 1 8.4-2.2" />
    </>,
    props,
  );

export const IconKey = (props: IconProps) =>
  base(
    <>
      <circle cx="7.5" cy="15.5" r="4.5" />
      <path d="m10.6 12.4 8.9-8.9" />
      <path d="m16.5 6.5 3 3" />
      <path d="m14 9 2.5 2.5" />
    </>,
    props,
  );

export const IconShuffle = (props: IconProps) =>
  base(
    <>
      <path d="m17 3 4 4-4 4" />
      <path d="M3 7h4a4 4 0 0 1 3.4 1.9" />
      <path d="M21 7h-6.6c-.9 0-1.7.4-2.3 1.1L8 14" />
      <path d="m17 21 4-4-4-4" />
      <path d="M3 17h4c.9 0 1.7-.4 2.3-1.1l1-1.2" />
      <path d="M14.4 15.1c.6.7 1.4 1.1 2.3 1.1H21" />
    </>,
    props,
  );

export const IconRotate = (props: IconProps) =>
  base(
    <>
      <path d="M3.5 12a8.5 8.5 0 1 1 2.6 6.1" />
      <path d="M3.5 17v-4h4" />
    </>,
    props,
  );

export const IconLink = (props: IconProps) =>
  base(
    <>
      <path d="M9.5 14.5 14.5 9.5" />
      <path d="M11 6.5 13 4.4a4 4 0 0 1 5.6 5.6L16.5 12" />
      <path d="M13 17.5l-2 2.1a4 4 0 0 1-5.6-5.6L7.5 12" />
    </>,
    props,
  );

export const IconChevronRight = (props: IconProps) => base(<path d="m9 6 6 6-6 6" />, props);

export const IconChevronLeft = (props: IconProps) => base(<path d="m15 6-6 6 6 6" />, props);

export const IconCopy = (props: IconProps) =>
  base(
    <>
      <rect x="9" y="9" width="12" height="12" rx="2" />
      <path d="M6 15H4.5A1.5 1.5 0 0 1 3 13.5v-9A1.5 1.5 0 0 1 4.5 3h9A1.5 1.5 0 0 1 15 4.5V6" />
    </>,
    props,
  );

export const IconCheck = (props: IconProps) => base(<path d="M4.5 12.5 9.5 17.5 19.5 6.5" />, props);

export const IconX = (props: IconProps) => base(<path d="m5 5 14 14M19 5 5 19" />, props);

export const IconAlert = (props: IconProps) =>
  base(
    <>
      <path d="M12 3.5 21.5 20H2.5L12 3.5Z" strokeLinejoin="round" />
      <path d="M12 10v4" />
      <circle cx="12" cy="17" r="0.25" fill="currentColor" />
    </>,
    props,
  );

export const IconRefresh = (props: IconProps) =>
  base(
    <>
      <path d="M20 11a8 8 0 0 0-14.6-4.5M4 13a8 8 0 0 0 14.6 4.5" />
      <path d="M5.4 6.5H3.4v-2M18.6 17.5h2v2" />
    </>,
    props,
  );

export const IconEye = (props: IconProps) =>
  base(
    <>
      <path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12Z" />
      <circle cx="12" cy="12" r="2.75" />
    </>,
    props,
  );

export const IconEyeOff = (props: IconProps) =>
  base(
    <>
      <path d="M3 3l18 18" />
      <path d="M10.6 5.7A9.9 9.9 0 0 1 12 5.5c6 0 9.5 6.5 9.5 6.5a15.6 15.6 0 0 1-3.3 4M6.6 6.8C4 8.5 2.5 12 2.5 12s3.5 6.5 9.5 6.5c1.2 0 2.3-.2 3.3-.6" />
      <path d="M9.9 14.1a2.75 2.75 0 0 0 3.9-3.9" />
    </>,
    props,
  );

export const IconZap = (props: IconProps) => base(<path d="M13 2 4 14h6l-1 8 9-12h-6l1-8Z" strokeLinejoin="round" />, props);

export const IconGrid = (props: IconProps) =>
  base(
    <>
      <rect x="3" y="3" width="7" height="7" rx="1" />
      <rect x="14" y="3" width="7" height="7" rx="1" />
      <rect x="3" y="14" width="7" height="7" rx="1" />
      <rect x="14" y="14" width="7" height="7" rx="1" />
    </>,
    props,
  );
