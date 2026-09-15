ALTER TABLE credit_packages
    ADD COLUMN IF NOT EXISTS product_id TEXT;

UPDATE credit_packages
SET product_id = CASE name
    WHEN 'Starter' THEN 'devtester_credits_starter'
    WHEN 'Pro' THEN 'devtester_credits_pro'
    WHEN 'Studio' THEN 'devtester_credits_studio'
    ELSE product_id
END
WHERE product_id IS NULL;

INSERT INTO credit_packages (name, price, credits, bonus_credits, product_id)
VALUES ('Studio', 499000, 7500, 1500, 'devtester_credits_studio')
ON CONFLICT DO NOTHING;

ALTER TABLE credit_packages
    ALTER COLUMN product_id SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS credit_packages_product_id_idx
    ON credit_packages(product_id);

CREATE TABLE IF NOT EXISTS google_play_purchases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    purchase_token TEXT NOT NULL UNIQUE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    package_id UUID NOT NULL REFERENCES credit_packages(id),
    product_id TEXT NOT NULL,
    credits_awarded INTEGER NOT NULL CHECK (credits_awarded > 0),
    bonus_credits_awarded INTEGER NOT NULL CHECK (bonus_credits_awarded >= 0),
    status TEXT NOT NULL DEFAULT 'fulfilled' CHECK (status IN ('fulfilled', 'acknowledged')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    acknowledged_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS google_play_purchases_user_idx
    ON google_play_purchases(user_id, created_at DESC);
