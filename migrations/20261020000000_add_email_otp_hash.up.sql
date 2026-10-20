alter table {{ index .Options "Namespace" }}.one_time_tokens
    add column if not exists otp_hash text not null default '';
