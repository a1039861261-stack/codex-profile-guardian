export function GuardianMark({ className = "" }) {
  return (
    <svg
      className={className}
      viewBox="0 0 48 48"
      role="img"
      aria-label="Guardian Mark"
      focusable="false"
    >
      <path
        d="M24 4 38 9v10.2C38 28.4 32.6 36.7 24 42c-8.6-5.3-14-13.6-14-22.8V9z"
        fill="none"
        stroke="currentColor"
        strokeWidth="3.1"
        strokeLinejoin="round"
      />
      <path
        d="M14.5 22h8.2m0 0 8.8-5.8M22.7 22l8.8 5.8"
        fill="none"
        stroke="currentColor"
        strokeWidth="3.1"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <circle cx="14.5" cy="22" r="2.6" fill="currentColor" />
      <circle cx="31.5" cy="16.2" r="2.6" fill="currentColor" />
      <circle cx="31.5" cy="27.8" r="2.6" fill="currentColor" />
    </svg>
  );
}
