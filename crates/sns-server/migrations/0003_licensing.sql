-- Per-org licensing: plan, seat count, trial/paid status. Seats are enforced at device
-- registration. One row per org.
CREATE TABLE IF NOT EXISTS licenses (
    org_id     BIGINT PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
    plan       TEXT NOT NULL DEFAULT 'trial',   -- 'trial' | 'paid'
    seats      INT  NOT NULL DEFAULT 5,          -- max devices allowed
    status     TEXT NOT NULL DEFAULT 'active',   -- 'active' | 'suspended'
    trial_ends TIMESTAMPTZ,                       -- NULL for paid plans
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
