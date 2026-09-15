CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    credits_balance INTEGER NOT NULL DEFAULT 50 CHECK (credits_balance >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE applications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    developer_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    app_name TEXT NOT NULL,
    playstore_link TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'in_progress', 'completed', 'cancelled')),
    required_testers INTEGER NOT NULL DEFAULT 12 CHECK (required_testers BETWEEN 1 AND 100),
    start_date DATE,
    end_date DATE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE tester_assignments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    tester_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'completed', 'cancelled')),
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(application_id, tester_id)
);

CREATE TABLE daily_checkins (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    assignment_id UUID NOT NULL REFERENCES tester_assignments(id) ON DELETE CASCADE,
    day_number INTEGER NOT NULL CHECK (day_number BETWEEN 1 AND 14),
    feedback_text TEXT NOT NULL,
    screenshot_url TEXT,
    is_verified BOOLEAN NOT NULL DEFAULT TRUE,
    checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(assignment_id, day_number)
);

CREATE TABLE credit_transactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    amount INTEGER NOT NULL,
    type TEXT NOT NULL CHECK (type IN ('earned', 'spent', 'purchased', 'bonus')),
    description TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE credit_packages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    price NUMERIC(12, 2) NOT NULL CHECK (price >= 0),
    credits INTEGER NOT NULL CHECK (credits > 0),
    bonus_credits INTEGER NOT NULL DEFAULT 0 CHECK (bonus_credits >= 0)
);

CREATE INDEX applications_status_idx ON applications(status, created_at DESC);
CREATE INDEX checkins_assignment_idx ON daily_checkins(assignment_id, day_number);
CREATE INDEX credit_transactions_user_idx ON credit_transactions(user_id, created_at DESC);
CREATE UNIQUE INDEX active_assignment_idx ON tester_assignments(application_id, tester_id) WHERE status = 'active';

INSERT INTO credit_packages (name, price, credits, bonus_credits)
VALUES ('Starter', 49000, 500, 50), ('Pro', 199000, 2500, 500)
ON CONFLICT DO NOTHING;
