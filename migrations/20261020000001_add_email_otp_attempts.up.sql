create table if not exists {{ index .Options "Namespace" }}.email_otp_attempts (
    key text primary key,
    window_id uuid not null,
    attempts integer not null check (attempts >= 0),
    expires_at timestamptz not null
);

create index if not exists email_otp_attempts_expires_at_idx
    on {{ index .Options "Namespace" }}.email_otp_attempts (expires_at);
