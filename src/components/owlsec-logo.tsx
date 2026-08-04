import { cn } from "@/lib/utils";

export function OwlSecLogo({
  className,
  title = "OwlSec",
}: {
  className?: string;
  title?: string;
}) {
  return (
    <svg
      viewBox="0 0 40 40"
      role="img"
      aria-label={title}
      className={cn("h-full w-full", className)}
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      <title>{title}</title>
      <path
        d="M20 3.2 L33.4 7.2 C33.4 18.8 30.4 28 20 36.8 C9.6 28 6.6 18.8 6.6 7.2 Z"
        className="fill-[color-mix(in_oklch,var(--primary)_10%,transparent)] stroke-[color-mix(in_oklch,var(--foreground)_55%,transparent)]"
        strokeWidth="1.25"
        strokeLinejoin="round"
      />
      <path
        d="M12.5 9.5 L15.6 13.4 L11.2 13.4 Z"
        className="fill-[color-mix(in_oklch,var(--foreground)_75%,transparent)]"
      />
      <path
        d="M27.5 9.5 L28.8 13.4 L24.4 13.4 Z"
        className="fill-[color-mix(in_oklch,var(--foreground)_75%,transparent)]"
      />
      <path
        d="M10.5 15.2 C13.5 12.6 26.5 12.6 29.5 15.2"
        className="stroke-[color-mix(in_oklch,var(--foreground)_45%,transparent)]"
        strokeWidth="1"
        strokeLinecap="round"
        fill="none"
      />
      <circle
        cx="15.2"
        cy="19.4"
        r="3.6"
        className="fill-[var(--background)] stroke-[var(--foreground)]"
        strokeWidth="1.2"
      />
      <circle
        cx="24.8"
        cy="19.4"
        r="3.6"
        className="fill-[var(--background)] stroke-[var(--foreground)]"
        strokeWidth="1.2"
      />
      <circle cx="15.2" cy="19.4" r="1.5" className="fill-[var(--primary)]" />
      <circle cx="24.8" cy="19.4" r="1.5" className="fill-[var(--primary)]" />
      <circle cx="15.7" cy="18.9" r="0.5" className="fill-[var(--background)]" />
      <circle cx="25.3" cy="18.9" r="0.5" className="fill-[var(--background)]" />
      <path d="M20 21.4 L18.6 24.2 L21.4 24.2 Z" className="fill-[var(--primary)]" />
      <path
        d="M20 25.4 V31"
        className="stroke-[color-mix(in_oklch,var(--foreground)_35%,transparent)]"
        strokeWidth="1"
        strokeLinecap="round"
      />
      <path
        d="M16 27.6 C18 29.4 22 29.4 24 27.6"
        className="stroke-[color-mix(in_oklch,var(--foreground)_35%,transparent)]"
        strokeWidth="1"
        strokeLinecap="round"
        fill="none"
      />
    </svg>
  );
}
